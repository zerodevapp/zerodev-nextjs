import { USDT_DECIMALS, VAULT_ADDRESS } from "@/app/ModularZerodev"
import { big2Bigint } from "@/app/bn"
import { vaultAbi } from "@/app/types/wagmi/generated"
import { Address, encodeFunctionData } from "viem"

export class VaultProxy {
    getDepositCallData(trader: Address, amount: Big) {
        return {
            to: VAULT_ADDRESS,
            value: 0n,
            data: encodeFunctionData({
                abi: vaultAbi,
                functionName: "deposit",
                args: [trader, big2Bigint(amount, USDT_DECIMALS)],
            }),
        }
    }

    getSetAuthorizationCallData(authorized: Address, isAuthorized: boolean) {
        return {
            to: VAULT_ADDRESS,
            value: 0n,
            data: encodeFunctionData({
                abi: vaultAbi,
                functionName: "setAuthorization",
                args: [authorized, isAuthorized],
            }),
        }
    }

}