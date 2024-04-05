export const MockRequestorAbi = [
    {
        inputs: [
            { internalType: "address", name: "kernel", type: "address" },
            { internalType: "bytes32", name: "hash", type: "bytes32" },
            { internalType: "bytes", name: "signature", type: "bytes" },
        ],
        name: "verifySignature",
        outputs: [{ internalType: "bool", name: "", type: "bool" }],
        stateMutability: "payable",
        type: "function",
    },
] as const
