# 🚗 V2X Secure Authentication & Data Transfer Protocol

V2X Secure Authentication Protocol is a lightweight cryptographic solution designed to secure communication between vehicles (V2V) and between vehicles and infrastructure (V2I) in Cellular Vehicle-to-Everything (C-V2X) systems. The protocol focuses on mutual authentication using Elliptic Curve Cryptography (ECC) and Zero-Knowledge Proofs (ZKP) to ensure that only legitimate vehicles and infrastructure nodes can participate in the network.

## 🧱 Network Architecture

The V2X Secure Authentication Protocol is designed around a three-tier architecture that mirrors real-world C-V2X deployments. Each entity—Vehicle, Roadside Unit (RSU), and Trusted Authority (TA)—is implemented as a distinct module within the project, facilitating modular development and testing.

1. Vehicle (On-Board Unit - OBU)
    * Role: Acts as a mobile node that initiates communication, authenticates itself to RSUs, and exchanges safety-critical messages with other vehicles and infrastructure.
    * Responsiblities:
      * Generates and manages its own ECC key pair using ECDSA.
      * Perform mutual authentication with Road Side Unit.
      * Perform data transfer with road side units (V2I).
      
    * Implementation: Located in the /Vehicle/ directory, containing scripts for key generation, authentication processes, and message handling.

3. Roadside Unit (RSU)
   * Role: Serves as a stationary intermediary that facilitates authentication between vehicles and the Trusted Authority.
   * Responsibilities:
     * Receives authentication requests from vehicles.
     * Receives data transferfrom vehicles.
     * Communicate with TA to validate credentials.
     * Manage sessions keys for secure communication.
   * Implementation: Found in the /RoadSideUnit/ directory, encompassing code for handling vehicle interactions and liaising with the TA.

4. Trusted Authority (TA)
    * Role: Functions as the central authority responsible for managing cryptographic credentials & identitiy credentials.
    * Responsibilities: 
      * Registers vehicles and RSUs, issuing unique identifiers and cryptographic materials.
      * Validates vehicle's authentication requests relayed by RSUs.
      * Authenticate RSU.
      * Maintains a secure database of registered entities.
   * Implementation: Contained within the /TrustedAuthority/ directory, including scripts for entity registration, credential issuance, and authentication validation.