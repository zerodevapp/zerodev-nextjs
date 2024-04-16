import { CLEARING_HOUSE_ADDRESS } from "@/app/ModularZerodev"
import { clearingHouseAbi } from "@/app/types/wagmi/generated"
import { Address, encodeFunctionData } from "viem"

export class ClearingHouseProxy {
    getSetAuthorizationCallData(authorized: Address, isAuthorized: boolean) {
        return {
            to: CLEARING_HOUSE_ADDRESS,
            value: 0n,
            data: encodeFunctionData({
                abi: clearingHouseAbi,
                functionName: "setAuthorization",
                args: [authorized, isAuthorized],
            }),
        }
    }
}