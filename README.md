# PassCheck_Z: FHE-based Password Strength Check

PassCheck_Z is a privacy-preserving password strength checking tool powered by Zama's Fully Homomorphic Encryption (FHE) technology. This innovative application allows users to input encrypted passwords and assess their strength without ever exposing sensitive information. By utilizing FHE, PassCheck_Z ensures that your password evaluations remain confidential and secure.

## The Problem

In today's digital landscape, password security is paramount. Many password strength checking tools require users to input their passwords in cleartext, creating a significant risk of data exposure. Cyber threats, data breaches, and unauthorized access pose serious risks to individuals and organizations alike. When passwords are transmitted as plain text, they can easily be intercepted and misused. The need for privacy-focused solutions that assess password strength without compromising user security has never been more urgent.

## The Zama FHE Solution

Fully Homomorphic Encryption (FHE) provides a robust solution to this pressing privacy issue. With FHE, computations can be performed directly on encrypted data, making it impossible for third parties to access the underlying information. This means that, using Zama's sophisticated libraries, PassCheck_Z can evaluate password strength metrics without ever needing to expose the password itself.

By leveraging fhevm, PassCheck_Z processes encrypted password inputs to determine strength and potential risk of exposure. This approach not only enhances privacy but also builds user trust, knowing their sensitive data is never compromised.

## Key Features

- 🔒 **Privacy-Preserving Evaluations**: Assess password strength without exposing cleartext data.
- ⚙️ **Dynamic Rule Matching**: Utilize advanced algorithms to evaluate password complexity based on customizable criteria.
- 🛡️ **Enhanced Security Awareness**: Educate users on password best practices and potential risks.
- 🚦 **User-Friendly Interface**: Simple input fields and clear rating indicators for a seamless experience.
- 🎯 **Real-Time Feedback**: Instant strength feedback allows users to adjust passwords on-the-fly.

## Technical Architecture & Stack

PassCheck_Z is built using a powerful tech stack centered around Zama's FHE technology. The key components include:

- **Zama's FHE Libraries**: 
  - **fhevm** for processing encrypted inputs.
- **Frontend Technologies**: 
  - HTML/CSS for structuring the user interface.
  - JavaScript for dynamic user interactions.
- **Backend Technologies**:
  - A secure server environment to handle encrypted computations.

The architecture ensures that every aspect of password strength evaluation occurs without sacrificing the user's privacy or security.

## Smart Contract / Core Logic

Here is a simplified pseudo-code example demonstrating how PassCheck_Z leverages Zama's technology to assess password strength:solidity
pragma solidity ^0.8.0;

contract PassCheck {
    // Function to encrypt and check password strength
    function checkPasswordStrength(uint64 encryptedPassword) public view returns (string memory) {
        uint64 strengthScore = TFHE.add(encryptedPassword, 0); // Placeholder for strength calculation
        string memory strengthLevel = "";

        if (strengthScore < 5) {
            strengthLevel = "Weak";
        } else if (strengthScore < 8) {
            strengthLevel = "Moderate";
        } else {
            strengthLevel = "Strong";
        }

        return strengthLevel;
    }
}

This snippet exemplifies how a password evaluation function might be designed using Solidity, integrating FHE capabilities to protect user data while still performing necessary computations.

## Directory Structure

The project directory structure for PassCheck_Z is as follows:
PassCheck_Z/
├── frontend/
│   ├── index.html
│   ├── styles.css
│   └── scripts.js
├── backend/
│   ├── PassCheck.sol          # Smart contract for password strength checking
│   └── main.py                # Python script for additional backend logic
└── README.md

This structure promotes organization, enhancing collaboration and maintainability.

## Installation & Setup

To set up PassCheck_Z, please ensure you have the following prerequisites:

1. **Node.js** installed on your machine.
2. **Python** (with pip) installed for backend operations.

### Prerequisites

1. Install necessary dependencies via npm:bash
   npm install fhevm

2. Install backend requirements using pip:bash
   pip install concrete-ml

## Build & Run

Once your environment is set up, you can build and run the application with the following commands:

1. For frontend:
   - Open the `index.html` file in your preferred web browser.

2. For backend:
   - Execute the following command to start the Python backend server:bash
   python main.py

3. Compile the smart contract using:bash
   npx hardhat compile

This process will prepare your environment to handle encrypted password strength evaluations seamlessly.

## Acknowledgements

Special thanks to Zama for providing the open-source FHE primitives that make projects like PassCheck_Z possible. Their commitment to privacy-preserving technology empowers developers to build secure applications that prioritize user confidentiality. 

By utilizing Zama's FHE capabilities, PassCheck_Z represents a significant step forward in creating secure, user-friendly tools that address pressing concerns in password security.

