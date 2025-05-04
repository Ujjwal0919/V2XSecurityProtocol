# 🚗 V2X Secure Authentication & Data Transfer Protocol

V2X Secure Authentication Protocol is a lightweight cryptographic solution designed to secure communication between vehicles (V2V) and between vehicles and infrastructure (V2I) in Cellular Vehicle-to-Everything (C-V2X) systems. The protocol focuses on mutual authentication using Elliptic Curve Cryptography (ECC) and Zero-Knowledge Proofs (ZKP) to ensure that only legitimate vehicles and infrastructure nodes can participate in the network.

## 🧱 Network Architecture

The V2X Secure Authentication Protocol is designed around a three-tier architecture that mirrors real-world C-V2X deployments. Each entity—Vehicle, Roadside Unit (RSU), and Trusted Authority (TA)—is implemented as a distinct module within the project, facilitating modular development and testing.

1. **Vehicle (On-Board Unit - OBU)**
    * **Role**: Acts as a mobile node that initiates communication, authenticates itself to RSUs, and exchanges safety-critical messages with other vehicles and infrastructure.
    * **Responsiblities**:
      * Generates and manages its own ECC key pair using ECDSA.
      * Perform mutual authentication with Road Side Unit.
      * Perform data transfer with road side units (V2I).
      
    * **Implementation**: Located in the ```/Vehicle/``` directory, containing scripts for key generation, authentication processes, and message handling.

3. **Roadside Unit (RSU)**
   * **Role**: Serves as a stationary intermediary that facilitates authentication between vehicles and the Trusted Authority.
   * **Responsibilities**:
     * Receives authentication requests from vehicles.
     * Receives data transferfrom vehicles.
     * Communicate with TA to validate credentials.
     * Manage sessions keys for secure communication.
   * **Implementation**: Found in the ```/RoadSideUnit/``` directory, encompassing code for handling vehicle interactions and liaising with the TA.

4. **Trusted Authority (TA)**
    * **Role**: Functions as the central authority responsible for managing cryptographic credentials & identitiy credentials.
    * **Responsibilities**: 
      * Registers vehicles and RSUs, issuing unique identifiers and cryptographic materials.
      * Validates vehicle's authentication requests relayed by RSUs.
      * Authenticate RSU.
      * Maintains a secure database of registered entities.
   * **Implementation**: Contained within the ```/TrustedAuthority/``` directory, including scripts for entity registration, credential issuance, and authentication validation.


## 🗂️ Project Structure & Simulation Logic
This project simulates a secure V2X environment using three main components—Vehicle, Road Side Unit (RSU), and Trusted Authority (TA)—each implemented as a separate module. Every component follows a consistent structure for handling registration, authentication, and V2I data transfer.

```aiignore

── README.md
├── Road Side Unit
│ ├── Database
│ │ ├── rsu_db.db
│ ├── rsu_authentication.py
│ ├── rsu_broadcast.py
│ ├── main.py
│ ├── rsu_data_transfer.py
│ ├── rsu_data_transfer.txt
│ ├── rsu_helperfunction.py
│ ├── rsu_keys.txt
│ └── rsu_registration.py
├── TrustedAuthority
│ ├── DataBases
│ │ └── TAdb.db
│ ├── __init__.py
│ ├── main.py
│ ├── ta_authentication.py
│ ├── ta_helperfuntion.py
│ └── ta_registration.py
└── Vehicle
│ ├── main.py
│ ├── vehicle_authentication.py
│ ├── vehicle_data_transfer.py
│ └── vehicle_helperfunction.py
│ └── vehicle_registration.py

```

### 🛢️ Database Setup
The Trusted Authority (TA) and Road Side Unit (RSU) components rely on local SQLite databases to manage cryptographic credentials and session information. These databases must be set up manually before running the simulation.

### 🔧 Database Files

    Trusted Authority Database: Tdb.db

    RSU Database: rsu_db.db

### Step-by-Step Table Creation
Follow these steps to manually create the tables using SQLite:

1. **Trusted Authority (TAdb.db)**
   * Open a terminal go to database directory and launch sqlite3 shell.
   ```bash
    cd /V2XSecurityProtocol/TrustedAuthority/DataBases
    sqlite3 TAdb.db
    ```
   * Create tables in trusted authority database.
   ```bash
    CREATE TABLE rsu_data (
    SID TEXT PRIMARY KEY,
    Chall TEXT,
    PubKey TEXT
    );
   ```
   ```bash
   CREATE TABLE vehicle_data (
    SID TEXT PRIMARY KEY,
    Chall TEXT,
    PubKey TEXT
    );
   ```
  
  ```bash
    CREATE TABLE TAKeys (
    PubKey TEXT,
    PrivKey TEXT
    );
   ```

2. **Road Side Unit (rsu_db.db)**
    * Open a terminal go to RSU's database directory and launch sqlite3 shell.
    ```bash
    cd /V2XSecureProtocol/RoadSideUnit/Database
    sqlite3 rsu_db.db
   ```
    * Create tables in road side unit database.
   ```bash
    CREATE TABLE rsu_data (
    SID TEXT PRIMARY KEY,
    PubKey TEXT
    );
    ```
   ```bash
    CREATE TABLE vehicle_cache (
    SID TEXT PRIMARY KEY,
    Chall TEXT
    );
    ```
   
## 🚀 Running the Setup
Each component in the V2X Secure Authentication Protocol—Vehicle, Road Side Unit (RSU), and Trusted Authority (TA)—is designed to run independently, making the system suitable for distributed and real-world testing.

### 🖥️ Deployment Setup
For our demonstration:
1. Vehicle: Raspberry Pi 8GB RAM
2. Road Side Unit (RSU): Raspberry Pi 8GB RAM
3. Trusted Authority (TA): PC with Intel i7 processor and 16GB RAM
4. Communication Interface: All entities are connected via the same Wi-Fi network for seamless communication.

### 🧪 Simulation Phases
The simulation is organized into three main phases:
#### 1️⃣ Registration Phase
The goal of this phase is to register each entity with the Trusted Authority and exchange public key credentials.
**Steps:**
1. Start the Trusted Authority service in trusted authority machine to listen for registration requests from vehicles and road side unit.
    ``` bash
   python3 ta_registration.py
   ```
2. Register roadside unit in RSU machine.
    ```bash
   python3 rsu_registration.py
   ```
3. Register the vehicle in vehicle's machine.
   ```bash
    python3 vehicle_registration.py
    ```
Each entity will generate public/private key pairs, save them in their memory (as a .txt file for demo) and send their public keys to TA. On the other hand TA, generate a unique SID and a Zero Knowledge Proof challenge for each entity. TA will generate a unique serial identity (SID) and a Zero Knowledge Proof challenge and them back to each entitiy along with TA's public key. Entities will save this identity information in their local storage.

### 2️⃣ Authentication Phase
In this phase, the Vehicle and RSU mutually authenticate each other using Zero-Knowledge Proof (ZKP), with the TA involved in credential validation. The authentication phase is divided into two different scenarios i.e 
1. Online Authentication
   In Online authentication a vehicle performs authentication through a RSU for the first time. At this time RSU doesn't have vehicle's credentials, hence RSU completes vehicle's authentication using trusted authority. Upon successful online authnetication, RSU saves vehicles's credentials in side inmemory cache.
2. Offline Authentication
   In offline authentication a vehicle performs authentication again with RSU from which it performed authentication before. In offline authentication RSU fetch the credentials from in memory cache and authenticate without contacting TA.

During vehicle's authentication, RSU also checks if it is authenticated with TA or not. If yes RSU attach its own session credentials with the message, other wise RSU performs its authentication as well.

1. Start the Trusted Authority authentication service from ```bash /TrustedAuthority``` directory.
   ```bash
   python3 main.py
   ```
2. Start the Road Side Unit server from ```bash /Road Side Unit``` directory.
   ```bash
   python3 main.py
   ```
   RSU wil start with two terminal, one that broadcast its public information like SID and public key and other one to receive authentication requests from vehicles.
3. Now, to start the authentication from vehicle change the directory to  ```bash /Vehicle``` and start the vehicle service.
  ```bash
   python3 main.py 
   [Vehicle] Searching For Nearby Road Side Unit ...
   [Vehicle] Received RSU Information from Broadcast:{'SID': '3e4a34803a60d2a0', 'PubKey': '0x8c7b4558ea5b90d7c11e21256f3ef9c2a715df85f5b46a69eb7d89ef3e805fe50'}
   [Vehicle] Connected To Road Side Unit:3e4a34803a60d2a0
   ************** VEHICLE MENU ***************
   1. Perform Authentication
   2. Perform Data Transfer (V2I)
   Enter Your Choice (1-2)1
   [Vehicle] Starting Authentication with Nearest Road Side Unit
   ```

### 3️⃣ V2I Data Transfer Phase (Vehicle to Infrastructure)