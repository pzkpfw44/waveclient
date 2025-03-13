Wave Secure Messaging – Technical Documentation
1. Introduction
The Wave Secure Messaging extension is a Chrome extension that enables secure post-quantum encrypted messaging. It uses modern cryptographic techniques—including the Kyber512 key encapsulation mechanism—and AES-GCM for message encryption. The extension integrates a WebAssembly (WASM) module (using the liboqs library) for post-quantum cryptography, a responsive popup user interface, and a Flask-based backend API for handling user authentication, key management, and message routing.
________________________________________
2. Architecture Overview
The system is divided into three main parts:
•	Frontend (Chrome Extension):
o	Popup UI: Provides a multi-tab interface for login/registration, managing contacts, chatting, and settings.
o	Background Script: Listens for messages and manages extension-level events.
o	WASM Integration: Uses a WebAssembly module (loaded via JavaScript and a dedicated web worker) to perform key encapsulation and decapsulation operations securely.
•	Backend API:
o	A Flask-based REST API (implemented in wave_api.py) that handles user registration, login, message storage, contact management, and key operations. Data is stored in file-based directories on the server.
•	Communication Flow:
o	The extension’s frontend interacts with the backend via HTTP requests.
o	Cryptographic operations occur locally in the browser using the loaded WASM module and JavaScript, ensuring that private keys remain secure.
________________________________________
3. Component Details
a. Manifest Configuration
The manifest.json file configures the extension’s properties, permissions, and resources:
•	Manifest Version & Basic Info: Defines the extension name ("Wave Secure Messaging"), version, and icons.
•	Background Service Worker: Specifies the background script (background.js) as a module.
•	Popup & Content Security: Provides the popup page (popup.html) and sets a content security policy that allows secure WASM execution.
•	Web Accessible Resources: Lists the WASM module (liboqs.wasm) and its JavaScript loader (liboqs.js) so they can be loaded from any URL.
manifest
b. Background Script
The background.js script handles inter-component messaging and logs incoming messages. Its primary role is to maintain background activity and provide an entry point for asynchronous communication.
(See file: background)
c. WebAssembly Module Integration
liboqs.js
This module asynchronously loads the liboqs.wasm file and sets up the environment required to call post-quantum cryptography functions (e.g., Kyber512 encapsulation and decapsulation). It creates a promise-based API so that the rest of the extension can call cryptographic functions once the module is ready.
(See file: liboqs)
oqsWorker.js
A dedicated WebWorker (oqsWorker.js) is provided to load and compile the WASM module in an isolated thread. This worker:
•	Fetches the WASM binary.
•	Compiles and instantiates the module.
•	Creates stub import objects for the WASM module’s required functions (functions, memory, tables, and globals).
•	Returns the module’s exports back to the main thread.
(See file: oqsWorker)
d. Popup User Interface
popup.html
Defines the HTML structure of the popup, featuring multiple sections:
•	Authentication: Login and registration forms.
•	Contacts: An interface to add and manage contacts.
•	Chat: A chat window where encrypted messages are sent and received.
•	Settings: Displays the user’s public key and account management options. Styling is applied inline as well as via the separate CSS file.
(See file: popup)
popup.js
This file is the core of the extension’s frontend logic. It:
•	Initializes the WASM module using the loader in liboqs.js.
•	Implements cryptographic operations: 
o	Key Encapsulation: Uses the OQS module to encapsulate a shared secret using the Kyber512 algorithm.
o	Double Encryption: Encrypts messages twice (once for the recipient and once for the sender) to ensure message integrity on both ends.
o	AES-GCM Encryption/Decryption: Encrypts/decrypts message content with shared secrets derived from key encapsulation.
•	Handles UI Interactions: 
o	Navigation between Contacts, Chat, and Settings.
o	Sending messages and rendering the chat conversation.
o	Authentication flows including login, registration, and session management.
•	Communicates with the backend API: Makes HTTP requests to endpoints for login, key retrieval, messaging, and contact management.
(See file: popup)
styles.css
Contains all CSS rules that style the popup UI, including layout, color schemes, button styles, and responsive design for the different sections of the application.
(See file: styles)
e. Backend API – wave_api.py
The backend API is implemented in wave_api.py using Flask. It manages:
•	User Sessions: Registration, login, and logout are handled with Flask sessions.
•	Key Management: 
o	Registration: Generates a Kyber512 keypair using the OQS library.
o	Private Key Storage: Encrypts the private key with AES-GCM using a key derived from the user’s password. The encryption uses a 16-byte salt as both the salt and IV.
•	Messaging: 
o	Accepts messages encrypted with two separate key encapsulation copies (one for the sender and one for the recipient).
o	Stores messages in folder structures derived from the public keys.
•	Contacts Management: 
o	Endpoints for adding, retrieving, and removing contacts.
•	Account Deletion: Removes user keys, contacts, and associated messages from the file system.
(See file: wave_api)
________________________________________
4. Cryptographic Workflow
Key Generation and Registration
•	Registration Flow:
When a user registers, the extension uses the Kyber512 algorithm to generate a keypair. 
o	The public key is saved in binary form and later encoded in Base64.
o	The private key is encrypted using AES-GCM. The encryption key is derived from the user’s password using PBKDF2 with SHA-256.
(See store_private_key in wave_api.py)
Message Encryption and Decryption
•	Encryption Process:
When sending a message, the extension performs “double encryption”: 
1.	Recipient Encryption: A shared secret is derived by encapsulating the recipient’s public key. The resulting shared secret is used with AES-GCM to encrypt the message.
2.	Sender Encryption: A separate encapsulation is performed using the sender’s own public key, ensuring that the sender also retains an encrypted copy.
o	Random nonces are generated for each AES-GCM encryption.
•	Decryption Process:
On receiving a message, the extension: 
1.	Uses the locally stored (and decrypted) private key to decapsulate the ephemeral ciphertext, retrieving the shared secret.
2.	Decrypts the message content using AES-GCM with the shared secret.
(Encryption/decryption functions are implemented in popup.js)
________________________________________
5. User Interface Overview
The extension’s popup UI is divided into several sections:
•	Authentication: 
o	Login and registration forms handle user credentials.
o	Once logged in, session management is maintained via backend API calls.
•	Contacts: 
o	Users can add contacts by inputting a Base64-encoded public key and a nickname.
o	Contacts are stored and later used to populate dropdowns for initiating chats.
•	Chat: 
o	Displays a conversation window where messages are decrypted and rendered.
o	Provides an input field for composing and sending encrypted messages.
•	Settings: 
o	Displays the current public key (which can be copied for sharing).
o	Provides an option to delete the account, which removes all local and server-stored data.
(See popup.html and popup.js for UI logic and styling in styles.css)
________________________________________
6. Backend API Endpoints
The backend API, built with Flask, offers the following endpoints:
•	/register (POST):
Registers a new user by generating a keypair and storing encrypted private key data.
•	/login (POST):
Logs in an existing user, retrieving session details and public key information.
•	/logout (POST):
Ends the user session.
•	/get_public_key (GET):
Returns the Base64-encoded public key for the logged-in user.
•	/get_encrypted_private_key (GET):
Returns the encrypted private key data (including salt and ciphertext).
•	/send_message (POST):
Accepts encrypted message data (both sender and recipient copies), stores the messages in file-based directories using hashed public keys.
•	/get_messages (GET):
Retrieves all messages for the logged-in user by scanning the relevant storage directory.
•	/add_contact (POST) & /remove_contact (POST):
Manage contact entries.
•	/delete_account (POST):
Deletes the user’s account and associated data.
(Detailed endpoint implementation is in wave_api.py)
________________________________________
7. Installation and Setup
Prerequisites
•	Browser: Google Chrome (or Chromium-based browser) with developer mode enabled.
•	Python Environment: Python 3.x with necessary packages: 
o	Flask
o	Flask-CORS
o	cryptography
o	oqs (if using the same library on the backend)
•	WASM File: Ensure liboqs.wasm is present and correctly referenced as a web accessible resource.
Steps
1.	Load the Extension:
o	Place all extension files (including manifest.json, JavaScript, HTML, CSS, and WASM files) in a directory.
o	Load the extension in Chrome via chrome://extensions (enable Developer Mode and “Load unpacked”).
2.	Setup the Backend API:
o	Install required Python packages (e.g., using pip).
o	Run the backend server using:
python wave_api.py
o	The API runs on port 5000 and must be reachable (as specified in the manifest’s host permissions).
3.	Testing:
o	Open the extension popup.
o	Register or log in.
o	Add contacts, and test sending/receiving encrypted messages.
________________________________________
8. Future Enhancements and Considerations
•	Security Audits:
Further review of cryptographic operations, secure storage, and session management is recommended.
•	Error Handling:
Enhance user feedback and error logging, especially for cryptographic exceptions.
•	UI/UX Improvements:
Consider additional features such as real-time notifications and improved accessibility.
•	Scalability:
Transition from file-based storage to a database for handling larger numbers of users/messages if needed.
________________________________________
9. Conclusion
The Wave Secure Messaging extension demonstrates how to combine post-quantum cryptography (using Kyber512 encapsulation) with modern web technologies to build a secure, user-friendly messaging system. With clear separation between frontend UI, WASM-based cryptographic operations, and a robust Flask backend API, the project offers a strong foundation for secure messaging in a post-quantum world.
Feel free to refer back to the source files for more details:
•	Background Script: background
•	WASM Loader: liboqs
•	Manifest Configuration: manifest
•	WASM Worker: oqsWorker
•	Popup UI and Logic: popup, popup
•	Styles: styles
•	Backend API: 

