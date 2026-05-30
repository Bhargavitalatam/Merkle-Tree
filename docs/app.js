// =====================================================================
// 🔗 Ethereum Merkle Verifier - Core Frontend Javascript Conductor
// =====================================================================

document.addEventListener("DOMContentLoaded", () => {
    // UI Elements Selector
    const rpcEndpointInput = document.getElementById("rpc-endpoint");
    const blockNumberInput = document.getElementById("block-number");
    const btnFetch = document.getElementById("btn-fetch");
    const rpcStatusText = document.getElementById("rpc-status-text");
    const rpcPulse = rpcStatusText.previousElementSibling;

    const inspectHeight = document.getElementById("inspect-height");
    const inspectTxCount = document.getElementById("inspect-tx-count");
    const inspectTime = document.getElementById("inspect-time");
    const inspectTxRoot = document.getElementById("inspect-tx-root");

    const txTableBody = document.getElementById("tx-table-body");
    const proverPanel = document.getElementById("prover-panel");
    const proverStatusPanel = document.getElementById("prover-status-panel");
    const proofBadge = document.getElementById("proof-badge");
    const targetTxHashTitle = document.getElementById("target-tx-hash-title");

    const proofExpectedRoot = document.getElementById("proof-expected-root");
    const proofCalculatedRoot = document.getElementById("proof-calculated-root");
    const proofStepsContainer = document.getElementById("proof-steps-container");

    const tamperTxData = document.getElementById("tamper-tx-data");
    const btnResetTamper = document.getElementById("btn-reset-tamper");

    // Global State variables
    let provider = null;
    let currentBlock = null;
    let selectedTxIndex = null;
    let selectedTxOriginalBytes = "";

    // Connect to RPC Provider
    function initializeProvider() {
        try {
            const url = rpcEndpointInput.value.trim();
            provider = new ethers.JsonRpcProvider(url);
            updateRpcStatus("green", "RPC Connected");
        } catch (e) {
            console.error("Provider initialization failed", e);
            updateRpcStatus("warning", "RPC Config Error");
        }
    }

    function updateRpcStatus(color, text) {
        rpcPulse.className = `pulse-dot ${color}`;
        rpcStatusText.innerText = text;
    }

    // Convert value to standard Quantity Hex (leading zeros stripped except to make even size)
    function toQuantityHex(value) {
        if (value === undefined || value === null) return "0x";
        let bigVal;
        try {
            if (typeof value === "string") {
                bigVal = BigInt(value);
            } else if (typeof value === "number") {
                bigVal = BigInt(value);
            } else {
                bigVal = BigInt(value);
            }
        } catch (err) {
            return "0x";
        }
        if (bigVal === 0n) return "0x";
        let hex = bigVal.toString(16);
        if (hex.length % 2 !== 0) {
            hex = "0" + hex;
        }
        return "0x" + hex;
    }

    // Convert value to standard Bytes Hex (even size, padded)
    function toBytesHex(val) {
        if (!val || val === "0x" || val === "") return "0x";
        let hex = val.startsWith("0x") ? val.slice(2) : val;
        if (hex.length % 2 !== 0) {
            hex = "0" + hex;
        }
        return "0x" + hex;
    }

    // Serialize access list field in EIP-2930 / EIP-1559 / EIP-4844 transactions
    function serializeAccessList(accessList) {
        if (!accessList) return [];
        return accessList.map(item => {
            const addr = toBytesHex(item.address);
            const storageKeys = (item.storageKeys || []).map(k => toBytesHex(k));
            return [addr, storageKeys];
        });
    }

    // Encode a transaction object matching EIP-2718 standards
    function encodeTransaction(tx) {
        const txType = tx.type === undefined ? 0 : parseInt(tx.type.toString());
        
        if (txType === 0) {
            // Legacy Transaction: RLP([nonce, gasPrice, gasLimit, to, value, data, v, r, s])
            const fields = [
                toQuantityHex(tx.nonce),
                toQuantityHex(tx.gasPrice),
                toQuantityHex(tx.gas || tx.gasLimit),
                toBytesHex(tx.to),
                toQuantityHex(tx.value),
                toBytesHex(tx.input || tx.data),
                toQuantityHex(tx.v),
                toQuantityHex(tx.r),
                toQuantityHex(tx.s)
            ];
            return ethers.encodeRlp(fields);
        } else if (txType === 1) {
            // EIP-2930: 0x01 + RLP([chainId, nonce, gasPrice, gasLimit, to, value, data, accessList, yParity, r, s])
            const fields = [
                toQuantityHex(tx.chainId),
                toQuantityHex(tx.nonce),
                toQuantityHex(tx.gasPrice),
                toQuantityHex(tx.gas || tx.gasLimit),
                toBytesHex(tx.to),
                toQuantityHex(tx.value),
                toBytesHex(tx.input || tx.data),
                serializeAccessList(tx.accessList),
                toQuantityHex(tx.v || tx.yParity),
                toBytesHex(tx.r),
                toBytesHex(tx.s)
            ];
            return "0x01" + ethers.encodeRlp(fields).slice(2);
        } else if (txType === 2) {
            // EIP-1559: 0x02 + RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, yParity, r, s])
            const fields = [
                toQuantityHex(tx.chainId),
                toQuantityHex(tx.nonce),
                toQuantityHex(tx.maxPriorityFeePerGas),
                toQuantityHex(tx.maxFeePerGas),
                toQuantityHex(tx.gas || tx.gasLimit),
                toBytesHex(tx.to),
                toQuantityHex(tx.value),
                toBytesHex(tx.input || tx.data),
                serializeAccessList(tx.accessList),
                toQuantityHex(tx.v || tx.yParity),
                toBytesHex(tx.r),
                toBytesHex(tx.s)
            ];
            return "0x02" + ethers.encodeRlp(fields).slice(2);
        } else if (txType === 3) {
            // EIP-4844: 0x03 + RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, maxFeePerBlobGas, blobVersionedHashes, yParity, r, s])
            const blobHashes = (tx.blobVersionedHashes || []).map(h => toBytesHex(h));
            const fields = [
                toQuantityHex(tx.chainId),
                toQuantityHex(tx.nonce),
                toQuantityHex(tx.maxPriorityFeePerGas),
                toQuantityHex(tx.maxFeePerGas),
                toQuantityHex(tx.gas || tx.gasLimit),
                toBytesHex(tx.to),
                toQuantityHex(tx.value),
                toBytesHex(tx.input || tx.data),
                serializeAccessList(tx.accessList),
                toQuantityHex(tx.maxFeePerBlobGas),
                blobHashes,
                toQuantityHex(tx.v || tx.yParity),
                toBytesHex(tx.r),
                toBytesHex(tx.s)
            ];
            return "0x03" + ethers.encodeRlp(fields).slice(2);
        } else {
            throw new Error(`Unsupported tx type: ${txType}`);
        }
    }

    // Convert hex string to Nibbles
    function bytesToNibbles(hexStr) {
        const hex = hexStr.startsWith("0x") ? hexStr.slice(2) : hexStr;
        const nibbles = [];
        for (let i = 0; i < hex.length; i++) {
            nibbles.push(parseInt(hex[i], 16));
        }
        return nibbles;
    }

    // Convert Nibbles back to hex string
    function nibblesToBytes(nibbles) {
        let hex = "";
        for (let i = 0; i < nibbles.length; i++) {
            hex += nibbles[i].toString(16);
        }
        return "0x" + hex;
    }

    // Hex compact prefix encoder
    function compactEncode(nibbles, isLeaf) {
        const odd = nibbles.length % 2 !== 0;
        let prefix = 0;
        if (isLeaf) prefix += 2;
        if (odd) prefix += 1;

        let compactNibbles;
        if (odd) {
            compactNibbles = [prefix, ...nibbles];
        } else {
            compactNibbles = [prefix, 0, ...nibbles];
        }
        return nibblesToBytes(compactNibbles);
    }

    // Hex compact prefix decoder
    function compactDecode(hexStr) {
        const nibbles = bytesToNibbles(hexStr);
        const prefix = nibbles[0];
        const isLeaf = (prefix & 2) !== 0;
        const odd = (prefix & 1) !== 0;
        if (odd) {
            return { nibbles: nibbles.slice(1), isLeaf };
        } else {
            return { nibbles: nibbles.slice(2), isLeaf };
        }
    }

    // MPT helper to generate inline nodes or Keccak hashes
    function nodeToRef(node) {
        if (node === null || node === undefined || node === "" || node === "0x") {
            return "0x";
        }
        const serialized = ethers.encodeRlp(node);
        const byteLen = (serialized.length - 2) / 2;
        if (byteLen < 32) {
            return node;
        }
        return ethers.keccak256(serialized);
    }

    // Recursive Modified Merkle Patricia Trie builder
    function buildMpt(kvPairs, nodeDb = null) {
        if (!kvPairs || kvPairs.length === 0) {
            return "0x";
        }
        
        let node;
        if (kvPairs.length === 1) {
            const [path, val] = kvPairs[0];
            node = [compactEncode(path, true), val];
        } else {
            // Longest common prefix search
            const firstPath = kvPairs[0][0];
            let commonLen = 0;
            for (let i = 0; i < firstPath.length; i++) {
                let match = true;
                for (const [path, _] of kvPairs) {
                    if (i >= path.length || path[i] !== firstPath[i]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    commonLen++;
                } else {
                    break;
                }
            }
            
            if (commonLen > 0) {
                const commonPrefix = firstPath.slice(0, commonLen);
                const strippedPairs = kvPairs.map(([path, val]) => [path.slice(commonLen), val]);
                const subNode = buildMpt(strippedPairs, nodeDb);
                node = [compactEncode(commonPrefix, false), nodeToRef(subNode)];
            } else {
                // Create branch node
                const children = Array(16).fill("0x");
                let value = "0x";
                
                const buckets = Array.from({ length: 16 }, () => []);
                for (const [path, val] of kvPairs) {
                    if (path.length === 0) {
                        value = val;
                    } else {
                        buckets[path[0]].push([path.slice(1), val]);
                    }
                }
                
                for (let i = 0; i < 16; i++) {
                    if (buckets[i].length > 0) {
                        children[i] = nodeToRef(buildMpt(buckets[i], nodeDb));
                    }
                }
                
                node = [...children, value];
            }
        }
        
        if (nodeDb && node) {
            const serialized = ethers.encodeRlp(node);
            const byteLen = (serialized.length - 2) / 2;
            const ref = byteLen >= 32 ? ethers.keccak256(serialized) : serialized;
            nodeDb[ref] = serialized;
        }
        
        return node;
    }

    // Reconstruct exact transactionsRoot hash
    function reconstructTransactionsRoot(transactions) {
        if (transactions.length === 0) {
            return ethers.keccak256("0x");
        }
        const kvPairs = [];
        for (let idx = 0; idx < transactions.length; idx++) {
            const txBytes = encodeTransaction(transactions[idx]);
            const keyRlp = ethers.encodeRlp(toQuantityHex(idx));
            kvPairs.push([bytesToNibbles(keyRlp), txBytes]);
        }
        
        // Sort pairs by key lexicographically
        kvPairs.sort((a, b) => {
            const pathA = a[0];
            const pathB = b[0];
            const len = Math.min(pathA.length, pathB.length);
            for (let i = 0; i < len; i++) {
                if (pathA[i] !== pathB[i]) return pathA[i] - pathB[i];
            }
            return pathA.length - pathB.length;
        });
        
        const rootNode = buildMpt(kvPairs);
        return ethers.keccak256(ethers.encodeRlp(rootNode));
    }

    // Generate standard RLP proof path
    function getMptProof(transactions, index) {
        const kvPairs = [];
        for (let idx = 0; idx < transactions.length; idx++) {
            const txBytes = encodeTransaction(transactions[idx]);
            const keyRlp = ethers.encodeRlp(toQuantityHex(idx));
            kvPairs.push([bytesToNibbles(keyRlp), txBytes]);
        }
        
        kvPairs.sort((a, b) => {
            const pathA = a[0];
            const pathB = b[0];
            const len = Math.min(pathA.length, pathB.length);
            for (let i = 0; i < len; i++) {
                if (pathA[i] !== pathB[i]) return pathA[i] - pathB[i];
            }
            return pathA.length - pathB.length;
        });

        const nodeDb = {};
        const rootNode = buildMpt(kvPairs, nodeDb);

        const targetKey = ethers.encodeRlp(toQuantityHex(index));
        const targetNibbles = bytesToNibbles(targetKey);

        const proof = [];
        let currNode = rootNode;
        let currNibbles = targetNibbles;

        while (currNode !== "0x" && currNode !== null && currNode !== undefined) {
            const serialized = ethers.encodeRlp(currNode);
            proof.push(serialized);

            if (currNode.length === 17) {
                if (currNibbles.length === 0) break;
                const nextNibble = currNibbles[0];
                const childRef = currNode[nextNibble];

                if (childRef === "0x" || childRef === "") break;
                if (Array.isArray(childRef)) {
                    currNode = childRef;
                } else {
                    currNode = ethers.decodeRlp(nodeDb[childRef]);
                }
                currNibbles = currNibbles.slice(1);
            } else if (currNode.length === 2) {
                const [encodedPath, childOrVal] = currNode;
                const { nibbles: pathNibbles, isLeaf } = compactDecode(encodedPath);

                // Assert prefix matches
                for (let i = 0; i < pathNibbles.length; i++) {
                    if (currNibbles[i] !== pathNibbles[i]) {
                        throw new Error("Trie traversal mismatch");
                    }
                }
                currNibbles = currNibbles.slice(pathNibbles.length);

                if (isLeaf) {
                    break;
                } else {
                    if (Array.isArray(childOrVal)) {
                        currNode = childOrVal;
                    } else {
                        currNode = ethers.decodeRlp(nodeDb[childOrVal]);
                    }
                }
            } else {
                break;
            }
        }
        return proof;
    }

    // Verify standard MPT proof on the simulated light client
    function verifyMptProof(expectedRoot, keyIndex, txValue, proof) {
        const targetKey = ethers.encodeRlp(toQuantityHex(keyIndex));
        const targetNibbles = bytesToNibbles(targetKey);

        let currExpectedHash = expectedRoot;
        let currNibbles = targetNibbles;

        const proofDb = {};
        for (const nodeBytes of proof) {
            proofDb[ethers.keccak256(nodeBytes)] = nodeBytes;
            const byteLen = (nodeBytes.length - 2) / 2;
            if (byteLen < 32) {
                proofDb[nodeBytes] = nodeBytes;
            }
        }

        for (let stepIdx = 0; stepIdx < proof.length; stepIdx++) {
            const nodeBytes = proof[stepIdx];
            const nodeHash = ethers.keccak256(nodeBytes);

            if (nodeHash !== currExpectedHash) {
                if (Array.isArray(currExpectedHash)) {
                    if (ethers.encodeRlp(currExpectedHash) !== nodeBytes) {
                        return false;
                    }
                } else {
                    if (nodeBytes !== currExpectedHash) {
                        return false;
                    }
                }
            }

            const node = ethers.decodeRlp(nodeBytes);

            if (node.length === 17) {
                if (currNibbles.length === 0) {
                    return node[16] === txValue;
                }
                const nextNibble = currNibbles[0];
                currExpectedHash = node[nextNibble];
                if (currExpectedHash === "0x" || currExpectedHash === "") {
                    return false;
                }
                currNibbles = currNibbles.slice(1);
            } else if (node.length === 2) {
                const [encodedPath, childOrVal] = node;
                const { nibbles: pathNibbles, isLeaf } = compactDecode(encodedPath);

                const prefixLen = pathNibbles.length;
                for (let i = 0; i < prefixLen; i++) {
                    if (currNibbles[i] !== pathNibbles[i]) {
                        return false;
                    }
                }
                currNibbles = currNibbles.slice(prefixLen);

                if (isLeaf) {
                    if (currNibbles.length > 0) return false;
                    return childOrVal === txValue;
                } else {
                    currExpectedHash = childOrVal;
                }
            } else {
                return false;
            }
        }
        return false;
    }

    // Render Transaction Ledger
    function renderTransactions(transactions) {
        if (!transactions || transactions.length === 0) {
            txTableBody.innerHTML = `<tr><td colspan="4" class="empty-state"><i class="fa-solid fa-circle-info"></i> Zero transactions in this block.</td></tr>`;
            return;
        }

        txTableBody.innerHTML = "";
        transactions.forEach((tx, idx) => {
            const tr = document.createElement("tr");
            tr.dataset.index = idx;
            
            const txType = tx.type === undefined ? 0 : parseInt(tx.type.toString());
            const badgeClass = `tx-badge type-${txType}`;
            const typeLabel = `Type ${txType}`;

            tr.innerHTML = `
                <td><strong>#${idx}</strong></td>
                <td class="hash-text">${tx.hash.slice(0, 14)}...${tx.hash.slice(-10)}</td>
                <td><span class="${badgeClass}">${typeLabel}</span></td>
                <td>
                    <button class="btn-secondary btn-verify-row" data-index="${idx}">
                        <i class="fa-solid fa-shield-halved"></i> Verify
                    </button>
                </td>
            `;

            tr.addEventListener("click", () => selectTransaction(idx));
            txTableBody.appendChild(tr);
        });
    }

    // Select Transaction & Open Prover Panel
    function selectTransaction(index) {
        selectedTxIndex = index;
        const tx = currentBlock.transactions[index];
        const rawBytes = encodeTransaction(tx);
        selectedTxOriginalBytes = rawBytes;

        // Highlight Active row
        document.querySelectorAll("#tx-table-body tr").forEach(row => {
            row.classList.remove("active-tx");
        });
        const activeRow = document.querySelector(`#tx-table-body tr[data-index="${index}"]`);
        if (activeRow) {
            activeRow.classList.add("active-tx");
        }

        // Show Prover
        proverPanel.style.display = "block";
        targetTxHashTitle.innerText = `${tx.hash.slice(0, 10)}...${tx.hash.slice(-8)}`;
        tamperTxData.value = rawBytes;

        runVerificationPlayground();
    }

    // Execute logic to verify & trace paths
    function runVerificationPlayground() {
        if (selectedTxIndex === null || !currentBlock) return;

        const expectedRoot = currentBlock.transactionsRoot;
        const calculatedRoot = reconstructTransactionsRoot(currentBlock.transactions);
        const inputBytes = tamperTxData.value.trim();

        // Generate MPT proof path using authentic block txs
        const proof = getMptProof(currentBlock.transactions, selectedTxIndex);

        // Run client-side proof validation
        const verified = verifyMptProof(expectedRoot, selectedTxIndex, inputBytes, proof);

        // Update UI panels based on validation success
        if (verified) {
            proverStatusPanel.className = "prover-status card-glow-success";
            proofBadge.innerHTML = `<i class="fa-solid fa-circle-check"></i> Verified`;
        } else {
            proverStatusPanel.className = "prover-status card-glow-danger";
            proofBadge.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> Tamper Detected`;
        }

        proofExpectedRoot.innerText = expectedRoot;
        proofCalculatedRoot.innerText = calculatedRoot;

        // Render proof nodes list
        proofStepsContainer.innerHTML = "";
        proof.forEach((nodeBytes, idx) => {
            const stepHash = ethers.keccak256(nodeBytes);
            const stepDiv = document.createElement("div");
            stepDiv.className = "proof-step-card";
            stepDiv.innerHTML = `
                <span class="proof-step-index">Node Layer ${idx}</span>
                <span class="hash-text smaller">${stepHash}</span>
            `;
            proofStepsContainer.appendChild(stepDiv);
        });
    }

    // Block Retrieval & MPT Reconstruction handler
    async function fetchBlockData() {
        btnFetch.disabled = true;
        btnFetch.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Fetching...`;
        updateRpcStatus("blue", "Loading block...");

        try {
            if (!provider) {
                initializeProvider();
            }

            let blockQuery = blockNumberInput.value.trim();
            if (!blockQuery) {
                blockQuery = "latest";
            }

            let blockNumberHex = blockQuery;
            if (blockQuery !== "latest" && !blockQuery.startsWith("0x")) {
                blockNumberHex = "0x" + parseInt(blockQuery).toString(16);
            }

            // Request raw block data including complete transaction contents
            const rawBlock = await provider.send("eth_getBlockByNumber", [blockNumberHex, true]);
            
            if (!rawBlock) {
                alert("Block not found or RPC returned empty result!");
                updateRpcStatus("warning", "Block not found");
                btnFetch.disabled = false;
                btnFetch.innerHTML = `<i class="fa-solid fa-arrow-down-up-lock"></i> Reconstruct`;
                return;
            }

            currentBlock = rawBlock;

            // Populate inspector card details
            inspectHeight.innerText = parseInt(rawBlock.number, 16).toString();
            inspectTxCount.innerText = rawBlock.transactions.length.toString();
            
            const timestamp = parseInt(rawBlock.timestamp, 16);
            inspectTime.innerText = new Date(timestamp * 1000).toLocaleString();
            inspectTxRoot.innerText = rawBlock.transactionsRoot;

            // Reconstruct Patricia Trie and check
            const calculatedRoot = reconstructTransactionsRoot(rawBlock.transactions);
            const matches = (calculatedRoot.toLowerCase() === rawBlock.transactionsRoot.toLowerCase());

            if (matches) {
                updateRpcStatus("green", "Root Match Success!");
            } else {
                updateRpcStatus("warning", "Root Mismatch (Check node provider type)");
            }

            // Render tx table ledger
            renderTransactions(rawBlock.transactions);

            // Hide previous prover details
            proverPanel.style.display = "none";
            selectedTxIndex = null;

        } catch (e) {
            console.error("Failed fetching block transactions", e);
            alert("Error connecting to Ethereum node: " + e.message);
            updateRpcStatus("danger", "RPC Connect Error");
        } finally {
            btnFetch.disabled = false;
            btnFetch.innerHTML = `<i class="fa-solid fa-arrow-down-up-lock"></i> Reconstruct`;
        }
    }

    // Event Bindings
    btnFetch.addEventListener("click", fetchBlockData);
    rpcEndpointInput.addEventListener("change", () => {
        initializeProvider();
    });

    tamperTxData.addEventListener("input", runVerificationPlayground);

    btnResetTamper.addEventListener("click", () => {
        if (selectedTxIndex !== null) {
            tamperTxData.value = selectedTxOriginalBytes;
            runVerificationPlayground();
        }
    });

    // Auto connect on start
    initializeProvider();
});
