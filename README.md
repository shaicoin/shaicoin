Shaicoin Core integration/staging tree
=====================================

## ShaiHive Mining Algorithm: Exploring Hamiltonian Graphs in Cryptocurrency Mining

The ShaiHive mining algorithm leverages Hamiltonian cycles—paths that visit each vertex of a graph exactly once before returning to the start. This method, recognized as an NP-complete problem due to its computational complexity, is integrated into cryptocurrency mining to combat the centralization issues seen in traditional approaches, aligning closely with the decentralized vision of Bitcoin's creator, Satoshi Nakamoto.

The algorithm includes a Verifiable Delay Function (VDF), a cryptographic technique that takes a predetermined time to compute but is quick to verify. This ensures that finding a solution to the Hamiltonian cycle is equally challenging for all miners, maintaining fairness in mining competition and preventing the concentration of mining power. Additionally, while the solution is difficult to compute, it is easily verifiable, supporting the security and reliability of the blockchain.


What is Shaicoin Core?
---------------------

Shaicoin Core connects to the Shaicoin peer-to-peer network to download and fully
validate blocks and transactions. It also includes a wallet and graphical user
interface, which can be optionally built.

Further information about Shaicoin Core is available in the [doc folder](/doc).

License
-------

Shaicoin Core is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/licenses/MIT.