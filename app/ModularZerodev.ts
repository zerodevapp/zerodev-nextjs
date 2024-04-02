import { SessionKeyStore } from "@/app/sessionKeyStore"
import { toECDSASigner, toWebAuthnSigner, WebAuthnMode } from "@zerodev/permission-validator/signers"
import {
    type Account,
    Address,
    Chain,
    createPublicClient,
    hashMessage,
    Hex,
    http,
    type Transport,
    WalletClient,
    encodeFunctionData,
    zeroAddress,
    toFunctionSelector,
    getAbiItem,
} from "viem"
import { optimism, sepolia } from "viem/chains"
import {
    toPermissionValidator,
    deserializePermissionAccount,
    serializePermissionAccount,
} from "@zerodev/permission-validator"
import { toCallPolicy, toSignatureCallerPolicy, toSudoPolicy } from "@zerodev/permission-validator/policies"
import { signerToEcdsaValidator } from "@zerodev/ecdsa-validator"
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
import { clearingHouseABI, vaultABI } from "@/app/types/wagmi/generated"
import { VaultProxy } from "@/app/VaultProxy"
import { ClearingHouseProxy } from "@/app/ClearingHouseProxy"
import { EntryPoint } from "permissionless/types"
import { TEST_ERC20Abi } from "./abis/Test_ERC20Abi"
import { createPimlicoBundlerClient } from "permissionless/clients/pimlico"
import { createPasskeyValidator, getPasskeyValidator, WEBAUTHN_VALIDATOR_ADDRESS_V07 } from "@zerodev/passkey-validator"

const BUNDLER_URL = `https://meta-aa-provider.onrender.com/api/v3/bundler/${process.env.NEXT_PUBLIC_ZERODEV_PROJECT_ID}?bundlerProvider=PIMLICO`
const PAYMASTER_URL = `https://meta-aa-provider.onrender.com/api/v2/paymaster/${process.env.NEXT_PUBLIC_ZERODEV_PROJECT_ID}?paymasterProvider=PIMLICO`
const PASSKEY_SERVER_URL = `https://passkeys.zerodev.app/api/v3/${process.env.NEXT_PUBLIC_ZERODEV_PROJECT_ID}`
export const CHAIN = sepolia

export const MOCK_REQUESTOR_ADDRESS = "0x67e0a05806A54f6C2162a91810BD50eFe28e0460" as Address
export const USDT_CONTRACT_ADDRESS = "0x94b008aA00579c1307B0EF2c499aD98a8ce58e58" as Address
export const USDT_DECIMALS = 6

export const VAULT_ADDRESS = "0x5aa45D0349c54D5BD241Dc6ece7b42601179ec59" as Address

export const CLEARING_HOUSE_ADDRESS = "0x4570e98cEF4b602B7A66f51CD6A51E2281075a46" as Address

export const ORDER_GATEWAY_V2_ADDRESS = "0x186841f8c1B9514D7B627A691b7d15831A17553B" as Address

// For testing purposes
export const Test_ERC20Address = "0x3870419Ba2BBf0127060bCB37f69A1b1C090992B" as Address

export class ModularZerodev<TChain extends Chain | undefined = Chain | undefined> {
    constructor(private readonly sessionKeyStore: SessionKeyStore) {}

    private getEntryPoint(): EntryPoint {
        return ENTRYPOINT_ADDRESS_V07
    }

    private getPublicClient() {
        return createPublicClient({
            transport: http(BUNDLER_URL),
        })
    }

    private getPimlicoBundlerClient = () => {
        console.log(
            "process.env.NEXT_PUBLIC_PIMLICO_BUNDLER_RPC_HOST",
            process.env.NEXT_PUBLIC_PIMLICO_BUNDLER_RPC_HOST,
        )
        if (!process.env.NEXT_PUBLIC_PIMLICO_BUNDLER_RPC_HOST)
            throw new Error("NEXT_PIMLICO_BUNDLER_RPC_HOST environment variable not set")

        return createPimlicoBundlerClient({
            chain: CHAIN,
            transport: http(`${process.env.NEXT_PUBLIC_PIMLICO_BUNDLER_RPC_HOST}`),
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

        const kernelAccount = await deserializePermissionAccount(this.getPublicClient(), serializedSessionKeyAccount)
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
        const kernelAccount = await deserializePermissionAccount(this.getPublicClient(), serializedSessionKeyAccount)
        console.log("kernelAccount", kernelAccount)
        const kernelClient = this.createKernelClient(CHAIN, kernelAccount)
        // const erc20Proxy = new Erc20Proxy(USDT_CONTRACT_ADDRESS, USDT_DECIMALS)
        // const vaultProxy = new VaultProxy()
        // const clearingHouseProxy = new ClearingHouseProxy()
        // const callData = await kernelClient.account.encodeCallData([
        //     erc20Proxy.getApproveCallData(VAULT_ADDRESS, Big(10)),
        //     // vaultProxy.getDepositCallData(kernelAccount.address, Big(10)),
        //     // vaultProxy.getSetAuthorizationCallData(ORDER_GATEWAY_V2_ADDRESS, true),
        //     // clearingHouseProxy.getSetAuthorizationCallData(ORDER_GATEWAY_V2_ADDRESS, true),
        // ])

        console.log("Test_ERC20Address", Test_ERC20Address)

        const callData = await kernelClient.account.encodeCallData([
            {
                to: Test_ERC20Address,
                value: 0n,
                data: encodeFunctionData({
                    abi: TEST_ERC20Abi,
                    functionName: "mint",
                    args: [kernelAccount.address, 100000000n],
                }),
            },
        ])

        console.log("callData", callData)

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

        const kernelAccount = await deserializePermissionAccount(this.getPublicClient(), serializedSessionKeyAccount)
        const kernelClient = this.createKernelClient(CHAIN, kernelAccount)
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
            policies: [await toSudoPolicy({})],
            entryPoint: this.getEntryPoint(),
        })

        console.log("create modularPermissionPlugin", Date.now() - start)

        const sessionKeyAccount = privateKeyToAccount(sessionPrivateKey)
        const sessionKeySigner = toECDSASigner({ signer: sessionKeyAccount })

        console.log("create sessionKeySigner", Date.now() - start)

        const sessionKeyModularPermissionPlugin = await toPermissionValidator(publicClient, {
            signer: sessionKeySigner,
            policies: [
                await toCallPolicy({
                    permissions: [
                        {
                            target: Test_ERC20Address,
                            valueLimit: BigInt(0),
                            abi: TEST_ERC20Abi,
                            functionName: "mint",
                            args: [null, null],
                        },
                    ],
                }),
                await toSignatureCallerPolicy({
                    allowedCallers: [MOCK_REQUESTOR_ADDRESS],
                }),
            ],
            entryPoint: this.getEntryPoint(),
        })

        console.log("create sessionKeyModularPermissionPlugin", Date.now() - start)

        const kernelAccount = await createKernelAccount(publicClient, {
            entryPoint: this.getEntryPoint(),
            plugins: {
                sudo: modularPermissionPlugin,
                regular: sessionKeyModularPermissionPlugin,
                entryPoint: this.getEntryPoint(),
            },
        })

        console.log("create kernelAccount", Date.now() - start)

        return kernelAccount
    }

    async createEoaKernelAccount(walletClient: WalletClient<Transport, TChain, Account>) {
        const start = Date.now()

        const publicClient = this.getPublicClient()
        const eoaSigner = walletClientToSmartAccountSigner(walletClient)
        const eoaEcdsaSigner = toECDSASigner({ signer: eoaSigner })

        console.log("eoaEcdsaSigner", eoaEcdsaSigner)

        console.log("create eoaEcdsaSigner", Date.now() - start)

        const modularPermissionPlugin = await toPermissionValidator(publicClient, {
            signer: eoaEcdsaSigner,
            policies: [await toSudoPolicy({})],
            entryPoint: this.getEntryPoint(),
        })

        console.log("create modularPermissionPlugin", modularPermissionPlugin)

        console.log("create modularPermissionPlugin", Date.now() - start)

        const kernelAccount = await createKernelAccount(publicClient, {
            entryPoint: this.getEntryPoint(),
            plugins: {
                entryPoint: this.getEntryPoint(),
                sudo: modularPermissionPlugin,
                executorData: {
                    executor: zeroAddress,
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
            policies: [await toSudoPolicy({})],
            entryPoint: this.getEntryPoint(),
        })

        const sessionKeyAccount = privateKeyToAccount(sessionPrivateKey)
        const sessionKeySigner = toECDSASigner({ signer: sessionKeyAccount })
        const sessionKeyModularPermissionPlugin = await toPermissionValidator(publicClient, {
            signer: sessionKeySigner,
            policies: [
                await toCallPolicy({
                    permissions: [
                        {
                            target: Test_ERC20Address,
                            valueLimit: BigInt(0),
                            abi: TEST_ERC20Abi,
                            functionName: "mint",
                            args: [null, null],
                        },
                    ],
                }),
                await toSignatureCallerPolicy({
                    allowedCallers: [MOCK_REQUESTOR_ADDRESS],
                }),
            ],
            entryPoint: this.getEntryPoint(),
        })

        return createKernelAccount(publicClient, {
            entryPoint: this.getEntryPoint(),
            plugins: {
                sudo: modularPermissionPlugin,
                regular: sessionKeyModularPermissionPlugin,
                entryPoint: this.getEntryPoint(),
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
                entryPoint: this.getEntryPoint(),
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
