import { SessionKeyStore } from "@/app/sessionKeyStore"
import { toECDSASigner, toWebAuthnSigner, WebAuthnMode } from "@zerodev/permissions/signers"
import {
    type Account,
    Address,
    Chain,
    createPublicClient,
    getAbiItem,
    hashMessage,
    Hex,
    http,
    toFunctionSelector,
    type Transport,
    WalletClient,
    zeroAddress,
} from "viem"
import { optimismSepolia } from "viem/chains"
import { deserializePermissionAccount, serializePermissionAccount, toPermissionValidator } from "@zerodev/permissions"
import { ParamCondition, toCallPolicy, toSignatureCallerPolicy, toSudoPolicy } from "@zerodev/permissions/policies"
import { privateKeyToAccount } from "viem/accounts"
import {
    createKernelAccount,
    createKernelAccountClient,
    createZeroDevPaymasterClient,
    KernelSmartAccount,
    KernelV3ExecuteAbi,
} from "@zerodev/sdk"
import {
    BundlerClient,
    createBundlerClient,
    ENTRYPOINT_ADDRESS_V07,
    getAction,
    walletClientToSmartAccountSigner,
} from "permissionless"
import { readContract } from "viem/actions"
import { MockRequestorAbi } from "./abis/MockRequestorAbi"
import { erc20Abi, Erc20Proxy } from "@/app/Erc20Proxy"
import Big from "big.js"
import { clearingHouseAbi, orderGatewayV2Abi, pythOracleAdapterAbi, vaultAbi } from "@/app/types/wagmi/generated"
import { EntryPoint } from "permissionless/types"
import { createPimlicoBundlerClient } from "permissionless/clients/pimlico"
import { VaultProxy } from "@/app/VaultProxy"
import { ClearingHouseProxy } from "@/app/ClearingHouseProxy"

const BUNDLER_URL = `https://rpc.zerodev.app/api/v2/bundler/${process.env.NEXT_PUBLIC_ZERODEV_PROJECT_ID}?bundlerProvider=PIMLICO`
const PAYMASTER_URL = `https://rpc.zerodev.app/api/v2/paymaster/${process.env.NEXT_PUBLIC_ZERODEV_PROJECT_ID}?paymasterProvider=PIMLICO`
const PASSKEY_SERVER_URL = `https://passkeys.zerodev.app/api/v3/${process.env.NEXT_PUBLIC_ZERODEV_PROJECT_ID}`
export const CHAIN = optimismSepolia

export const MOCK_REQUESTOR_ADDRESS = "0xF972dba9e3642d32050c3a9E6c1a1F8A809EB910" as Address
export const USDT_CONTRACT_ADDRESS = "0xA8Eba06366A8ad5E59Ef29477E7a4B384ea648Bf" as Address
export const USDT_DECIMALS = 6
export const VAULT_ADDRESS = "0x967A047e7B5f24cF574BA58389BA09a418EAf805" as Address
export const CLEARING_HOUSE_ADDRESS = "0x71c8c788fe1115A12d390b785AE8408cD959ba53" as Address
export const ORDER_GATEWAY_V2_ADDRESS = "0xc66974D9a1fd57283FF034b909D9BE09C0ccAFf1" as Address

export class ModularZerodev<TChain extends Chain | undefined = Chain | undefined> {
    constructor(private readonly sessionKeyStore: SessionKeyStore) {
    }

    private getEntryPoint(): EntryPoint {
        return ENTRYPOINT_ADDRESS_V07
    }

    private getPublicClient() {
        return createPublicClient({
            transport: http(BUNDLER_URL),
        })
    }

    private getPimlicoBundlerClient = () => {
        return createPimlicoBundlerClient({
            chain: CHAIN,
            transport: http(BUNDLER_URL),
            entryPoint: this.getEntryPoint(),
        })
    }

    async signInByPasskey(passkeyName: string, mode: WebAuthnMode, sessionPrivateKey?: Hex) {
        let kernelAccount: KernelSmartAccount<EntryPoint>
        if (sessionPrivateKey) {
            kernelAccount = await this.createPasskeySessionKeyKernelAccount(passkeyName, mode, sessionPrivateKey)
        } else {
            kernelAccount = await this.createPasskeyKernelAccount(passkeyName, mode)
        }
        console.log("kernelAccount", kernelAccount)

        if (sessionPrivateKey) {
            const serializedSessionKeyAccount = await serializePermissionAccount(kernelAccount, sessionPrivateKey)
            this.sessionKeyStore.getState().setSerializedSessionKeyAccount(serializedSessionKeyAccount)
        }
        return kernelAccount
    }

    async signInByEoa(walletClient: WalletClient<Transport, TChain, Account>, sessionPrivateKey?: Hex) {
        let kernelAccount: KernelSmartAccount<EntryPoint>
        if (sessionPrivateKey) {
            kernelAccount = await this.createEoaSessionKeyKernelAccount(walletClient, sessionPrivateKey)
        } else {
            kernelAccount = await this.createEoaKernelAccount(walletClient)
        }
        console.log("kernelAccount", kernelAccount)

        if (sessionPrivateKey) {
            const serializedSessionKeyAccount = await serializePermissionAccount(kernelAccount, sessionPrivateKey)
            this.sessionKeyStore.getState().setSerializedSessionKeyAccount(serializedSessionKeyAccount)
        }
        return kernelAccount
    }

    async signMessage(message: string) {
        const serializedSessionKeyAccount = this.sessionKeyStore.getState().serializedSessionKeyAccount
        if (!serializedSessionKeyAccount) {
            return undefined
        }

        const kernelAccount = await deserializePermissionAccount(
            this.getPublicClient(),
            this.getEntryPoint(),
            serializedSessionKeyAccount,
        )
        const kernelClient = this.createKernelClient(CHAIN, kernelAccount)
        const sig = await kernelClient.signMessage({
            message,
        })
        console.log("signMessage", sig)
        return sig
    }

    async sendUserOp(kernelAccount: KernelSmartAccount<EntryPoint>) {
        const kernelClient = this.createKernelClient(CHAIN, kernelAccount)
        const erc20Proxy = new Erc20Proxy(USDT_CONTRACT_ADDRESS, USDT_DECIMALS)
        const callData = await kernelClient.account.encodeCallData(
            erc20Proxy.getApproveCallData(VAULT_ADDRESS, Big(10)),
        )
        const userOpHash = await kernelClient.sendUserOperation({
            userOperation: {
                callData,
            },
        })

        const bundlerClient = this.getBundlerClient()
        const receipt = await bundlerClient.waitForUserOperationReceipt({ hash: userOpHash })
        console.log("sendUserOp", userOpHash, receipt.receipt.transactionHash)
    }

    async sendUserOpBySessionKey() {
        const serializedSessionKeyAccount = this.sessionKeyStore.getState().serializedSessionKeyAccount
        if (!serializedSessionKeyAccount) {
            return
        }

        console.log("serializedSessionKeyAccount", serializedSessionKeyAccount)
        const kernelAccount = await deserializePermissionAccount(
            this.getPublicClient(),
            this.getEntryPoint(),
            serializedSessionKeyAccount,
        )
        console.log("kernelAccount", kernelAccount)
        const kernelClient = this.createKernelClient(CHAIN, kernelAccount)
        const erc20Proxy = new Erc20Proxy(USDT_CONTRACT_ADDRESS, USDT_DECIMALS)
        const vaultProxy = new VaultProxy()
        const clearingHouseProxy = new ClearingHouseProxy()
        const callData = await kernelClient.account.encodeCallData([
            erc20Proxy.getApproveCallData(VAULT_ADDRESS, Big(10)),
            // vaultProxy.getDepositCallData(kernelAccount.address, Big(10)),
            // vaultProxy.getSetAuthorizationCallData(ORDER_GATEWAY_V2_ADDRESS, true),
            // clearingHouseProxy.getSetAuthorizationCallData(ORDER_GATEWAY_V2_ADDRESS, true),
        ])

        const userOpHash = await kernelClient.sendUserOperation({
            userOperation: {
                callData,
            },
        })
        const bundlerClient = this.getBundlerClient()
        const receipt = await bundlerClient.waitForUserOperationReceipt({ hash: userOpHash })
        console.log("sendUserOpBySessionKey", userOpHash, receipt.receipt.transactionHash)
    }

    async verifySignature(message: string, signature: string) {
        const serializedSessionKeyAccount = this.sessionKeyStore.getState().serializedSessionKeyAccount
        if (!serializedSessionKeyAccount) {
            return
        }

        const kernelAccount = await deserializePermissionAccount(
            this.getPublicClient(),
            this.getEntryPoint(),
            serializedSessionKeyAccount,
        )
        const kernelClient = this.createKernelClient(CHAIN, kernelAccount)
        console.log("kernelClient", kernelClient)
        const response = await getAction(
            kernelClient.account.client,
            readContract,
        )({
            abi: MockRequestorAbi,
            address: MOCK_REQUESTOR_ADDRESS,
            functionName: "verifySignature",
            args: [kernelClient.account.address, hashMessage(message), signature],
        })
        console.log("Signature verified response: ", response)
        return response
    }

    async createEoaSessionKeyKernelAccount(
        walletClient: WalletClient<Transport, TChain, Account>,
        sessionPrivateKey: Address,
    ) {
        const start = Date.now()

        const publicClient = this.getPublicClient()
        const eoaSigner = walletClientToSmartAccountSigner(walletClient)
        const eoaEcdsaSigner = toECDSASigner({ signer: eoaSigner })

        console.log("create eoaEcdsaSigner", Date.now() - start)

        const modularPermissionPlugin = await toPermissionValidator(publicClient, {
            signer: eoaEcdsaSigner,
            policies: [toSudoPolicy({})],
            entryPoint: this.getEntryPoint(),
        })

        console.log("create modularPermissionPlugin", Date.now() - start)

        const sessionKeyAccount = privateKeyToAccount(sessionPrivateKey)
        const sessionKeySigner = toECDSASigner({ signer: sessionKeyAccount })

        console.log("create sessionKeySigner", Date.now() - start)

        const sessionKeyModularPermissionPlugin = await toPermissionValidator(publicClient, {
            signer: sessionKeySigner,
            policies: this.getPolicies(),
            entryPoint: this.getEntryPoint(),
        })

        console.log("create sessionKeyModularPermissionPlugin", Date.now() - start)

        const kernelAccount = await createKernelAccount(publicClient, {
            entryPoint: this.getEntryPoint(),
            plugins: {
                sudo: modularPermissionPlugin,
                regular: sessionKeyModularPermissionPlugin,
                action: {
                    address: zeroAddress,
                    selector: toFunctionSelector(getAbiItem({ abi: KernelV3ExecuteAbi, name: "execute" })),
                },
            },
        })

        console.log("create kernelAccount", Date.now() - start)

        return kernelAccount
    }

    private getPolicies() {
        return [
            toCallPolicy({
                permissions: [
                    {
                        target: USDT_CONTRACT_ADDRESS,
                        valueLimit: BigInt(0),
                        abi: erc20Abi,
                        functionName: "approve",
                        args: [{ condition: ParamCondition.EQUAL, value: VAULT_ADDRESS }, null],
                    },
                    {
                        target: VAULT_ADDRESS,
                        valueLimit: BigInt(0),
                        // @ts-ignore
                        abi: vaultAbi,
                        // @ts-ignore
                        functionName: "deposit",
                        args: [null, null],
                    },
                    {
                        target: VAULT_ADDRESS,
                        valueLimit: BigInt(0),
                        // @ts-ignore
                        abi: vaultAbi,
                        // @ts-ignore
                        functionName: "withdraw",
                        args: [null],
                    },
                    {
                        target: VAULT_ADDRESS,
                        valueLimit: BigInt(0),
                        // @ts-ignore
                        abi: vaultAbi,
                        // functionName: "transferFundToMargin",
                        // args: [null, null],
                        selector: toFunctionSelector("transferFundToMargin(uint256,uint256)"),
                    },
                    {
                        target: VAULT_ADDRESS,
                        valueLimit: BigInt(0),
                        // @ts-ignore
                        abi: vaultAbi,
                        // functionName: "transferMarginToFund",
                        // args: [null, null],
                        selector: toFunctionSelector("transferMarginToFund(uint256,uint256)"),
                    },
                    {
                        target: VAULT_ADDRESS,
                        valueLimit: BigInt(0),
                        // @ts-ignore
                        abi: vaultAbi,
                        // @ts-ignore
                        functionName: "setAuthorization",
                        args: [null, null],
                    },
                    {
                        target: CLEARING_HOUSE_ADDRESS,
                        valueLimit: BigInt(0),
                        // @ts-ignore
                        abi: clearingHouseAbi,
                        // @ts-ignore
                        functionName: "setAuthorization",
                        args: [null, null],
                    },
                    {
                        target: CLEARING_HOUSE_ADDRESS,
                        valueLimit: BigInt(0),
                        // @ts-ignore
                        abi: pythOracleAdapterAbi,
                        // @ts-ignore
                        functionName: "updatePrice",
                        args: [null, null],
                    },
                    {
                        target: ORDER_GATEWAY_V2_ADDRESS,
                        valueLimit: BigInt(0),
                        // @ts-ignore
                        abi: orderGatewayV2Abi,
                        // @ts-ignore
                        functionName: "cancelOrder",
                        args: [null, null],
                    },
                    {
                        target: zeroAddress,
                    },
                ],
            }),
            toSignatureCallerPolicy({
                allowedCallers: [MOCK_REQUESTOR_ADDRESS],
            }),
        ]
    }

    async createEoaKernelAccount(walletClient: WalletClient<Transport, TChain, Account>) {
        const start = Date.now()

        const publicClient = this.getPublicClient()
        const eoaSigner = walletClientToSmartAccountSigner(walletClient)
        const eoaEcdsaSigner = toECDSASigner({ signer: eoaSigner })

        console.log("create eoaEcdsaSigner", Date.now() - start)

        const modularPermissionPlugin = await toPermissionValidator(publicClient, {
            signer: eoaEcdsaSigner,
            policies: [toSudoPolicy({})],
            entryPoint: this.getEntryPoint(),
        })

        console.log("create modularPermissionPlugin", Date.now() - start)

        const kernelAccount = await createKernelAccount(publicClient, {
            entryPoint: this.getEntryPoint(),
            plugins: {
                sudo: modularPermissionPlugin,
                action: {
                    address: zeroAddress,
                    selector: toFunctionSelector(getAbiItem({ abi: KernelV3ExecuteAbi, name: "execute" })),
                },
            },
        })

        console.log("create kernelAccount", Date.now() - start)

        return kernelAccount
    }

    async createPasskeySessionKeyKernelAccount(passkeyName: string, mode: WebAuthnMode, sessionPrivateKey: Address) {
        const publicClient = this.getPublicClient()

        const webAuthnModularSigner = await toWebAuthnSigner(publicClient, {
            passkeyName,
            passkeyServerUrl: PASSKEY_SERVER_URL,
            mode,
        })
        const modularPermissionPlugin = await toPermissionValidator(publicClient, {
            signer: webAuthnModularSigner,
            policies: [toSudoPolicy({})],
            entryPoint: this.getEntryPoint(),
        })

        const sessionKeyAccount = privateKeyToAccount(sessionPrivateKey)
        const sessionKeySigner = toECDSASigner({ signer: sessionKeyAccount })
        const sessionKeyModularPermissionPlugin = await toPermissionValidator(publicClient, {
            signer: sessionKeySigner,
            policies: this.getPolicies(),
            entryPoint: this.getEntryPoint(),
        })

        return createKernelAccount(publicClient, {
            entryPoint: this.getEntryPoint(),
            plugins: {
                sudo: modularPermissionPlugin,
                regular: sessionKeyModularPermissionPlugin,
                action: {
                    address: zeroAddress,
                    selector: toFunctionSelector(getAbiItem({ abi: KernelV3ExecuteAbi, name: "execute" })),
                },
            },
        })
    }

    async createPasskeyKernelAccount(passkeyName: string, mode: WebAuthnMode) {
        const publicClient = this.getPublicClient()
        const webAuthnModularSigner = await toWebAuthnSigner(publicClient, {
            passkeyName,
            passkeyServerUrl: PASSKEY_SERVER_URL,
            mode,
        })

        const modularPermissionPlugin = await toPermissionValidator(publicClient, {
            signer: webAuthnModularSigner,
            policies: [await toSudoPolicy({})],
            entryPoint: this.getEntryPoint(),
        })

        return createKernelAccount(publicClient, {
            entryPoint: this.getEntryPoint(),
            plugins: {
                sudo: modularPermissionPlugin,
                action: {
                    address: zeroAddress,
                    selector: toFunctionSelector(getAbiItem({ abi: KernelV3ExecuteAbi, name: "execute" })),
                },
            },
        })
    }

    createKernelClient<entryPoint extends EntryPoint>(chain: Chain, kernelAccount: KernelSmartAccount<entryPoint>) {
        const pimlicoBundlerClient = this.getPimlicoBundlerClient()
        return createKernelAccountClient({
            account: kernelAccount,
            chain,
            bundlerTransport: http(BUNDLER_URL),
            middleware: {
                gasPrice: async () => (await pimlicoBundlerClient.getUserOperationGasPrice()).fast,
                sponsorUserOperation: async ({ userOperation }) => {
                    const zerodevPaymaster = createZeroDevPaymasterClient({
                        chain,
                        transport: http(PAYMASTER_URL),
                        entryPoint: this.getEntryPoint(),
                    })
                    return zerodevPaymaster.sponsorUserOperation({
                        userOperation,
                        entryPoint: this.getEntryPoint(),
                    })
                },
            },
            entryPoint: this.getEntryPoint() as entryPoint,
        })
    }

    getBundlerClient(): BundlerClient<EntryPoint> {
        return createBundlerClient({
            chain: CHAIN,
            transport: http(BUNDLER_URL),
            entryPoint: this.getEntryPoint(),
        })
    }
}
