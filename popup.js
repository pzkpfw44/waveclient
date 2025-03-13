// popup.js
import createOQSModule from "./liboqs.js";

let oqs;
let currentUser = null;
let currentPassword = null;
let currentPrivateKey = null; // Uint8Array of decrypted private key
let currentPubKey = null;     // Your public key (base64) from /get_public_key
let allMessages = [];
let contactsMap = {};         // { publicKey: { nickname } }
let selectedContact = null;   // The recipient's public key (base64)

document.addEventListener("DOMContentLoaded", async function () {
  // Initialize OQS Module
  try {
    oqs = await createOQSModule();
    console.log("OQS WASM library loaded:", oqs);
  } catch (error) {
    console.error("Failed to initialize the extension:", error);
    alert("Initialization error. See console for details.");
    return;
  }
  
  // --------------------------------------------------------
  // Add a KeyEncapsulation wrapper to the oqs object if not defined
  // --------------------------------------------------------
  oqs.KeyEncapsulation = class {
    constructor(algorithm) {
      if (algorithm !== "Kyber512") {
        throw new Error("Unsupported algorithm: " + algorithm);
      }
      this.algorithm = algorithm;
    }
    async encapSecret(recipientPublicKeyBytes) {
      const pubKeySize = recipientPublicKeyBytes.length;
      const recipientPtr = oqs._malloc(pubKeySize);
      oqs.HEAPU8.set(recipientPublicKeyBytes, recipientPtr);
      const ciphertextSize = 768; // Adjust if needed.
      const sharedSecretSize = 32; // Expected for Kyber512.
      const ciphertextPtr = oqs._malloc(ciphertextSize);
      const sharedSecretPtr = oqs._malloc(sharedSecretSize);
      const ret = oqs._OQS_KEM_kyber_512_encaps(ciphertextPtr, sharedSecretPtr, recipientPtr);
      if (ret !== 0) {
        oqs._free(recipientPtr);
        oqs._free(ciphertextPtr);
        oqs._free(sharedSecretPtr);
        throw new Error("Encapsulation failed with error code " + ret);
      }
      const ciphertext = new Uint8Array(oqs.HEAPU8.buffer, ciphertextPtr, ciphertextSize);
      const sharedSecret = new Uint8Array(oqs.HEAPU8.buffer, sharedSecretPtr, sharedSecretSize);
      const ciphertextCopy = new Uint8Array(ciphertext);
      const sharedSecretCopy = new Uint8Array(sharedSecret);
      oqs._free(recipientPtr);
      oqs._free(ciphertextPtr);
      oqs._free(sharedSecretPtr);
      return { ciphertext: ciphertextCopy, sharedSecret: sharedSecretCopy };
    }
    async loadSecretKey(secretKeyBytes) {
      this.secretKey = secretKeyBytes;
    }
    async decapSecret(ciphertext) {
      if (!this.secretKey) {
        throw new Error("Secret key not loaded.");
      }
      const ciphertextSize = ciphertext.length;
      const ciphertextPtr = oqs._malloc(ciphertextSize);
      oqs.HEAPU8.set(ciphertext, ciphertextPtr);
      const secretKeySize = this.secretKey.length;
      const secretKeyPtr = oqs._malloc(secretKeySize);
      oqs.HEAPU8.set(this.secretKey, secretKeyPtr);
      const sharedSecretSize = 32;
      const sharedSecretPtr = oqs._malloc(sharedSecretSize);
      const ret = oqs._OQS_KEM_kyber_512_decaps(sharedSecretPtr, ciphertextPtr, secretKeyPtr);
      if (ret !== 0) {
        oqs._free(ciphertextPtr);
        oqs._free(secretKeyPtr);
        oqs._free(sharedSecretPtr);
        throw new Error("Decapsulation failed with error code " + ret);
      }
      const sharedSecret = new Uint8Array(oqs.HEAPU8.buffer, sharedSecretPtr, sharedSecretSize);
      const sharedSecretCopy = new Uint8Array(sharedSecret);
      oqs._free(ciphertextPtr);
      oqs._free(secretKeyPtr);
      oqs._free(sharedSecretPtr);
      return sharedSecretCopy;
    }
    free() {
      // No dynamic state to free in this wrapper.
    }
  };

  // ---------------------------
  // DOM Elements
  // ---------------------------
  const sendMessageBtn = document.getElementById("send-message-btn");
  const tabContactsLink = document.getElementById("tab-contacts");
  const tabChatLink = document.getElementById("tab-chat");
  const tabSettingsLink = document.getElementById("tab-settings");
  const logoutLink = document.getElementById("logout-btn");
  const userLabel = document.getElementById("user-label");

  const authContainer = document.getElementById("auth-container");
  const contactsContainer = document.getElementById("contacts-container");
  const chatContainer = document.getElementById("chat-container");
  const settingsContainer = document.getElementById("settings-container");

  const loginUsernameInput = document.getElementById("login-username");
  const loginPasswordInput = document.getElementById("login-password");
  const loginBtn = document.getElementById("login-btn");
  const regUsernameInput = document.getElementById("reg-username");
  const regPasswordInput = document.getElementById("reg-password");
  const registerBtn = document.getElementById("register-btn");

  const contactPublicKeyInput = document.getElementById("contact-public-key");
  const contactNicknameInput = document.getElementById("contact-nickname");
  const addContactBtn = document.getElementById("add-contact-btn");
  const contactsDiv = document.getElementById("contacts");

  const contactSelect = document.getElementById("contact-select");
  const messagesDiv = document.getElementById("messages");
  const messageTextInput = document.getElementById("message-text");

  const publicKeyDisplay = document.getElementById("public-key-display");
  const copyKeyBtn = document.getElementById("copy-key-btn");
  const cancelAccountBtn = document.getElementById("cancel-account-btn");

  // ---------------------------
  // Ensure All UI Components Are Fully Loaded
  // ---------------------------
  if (!tabContactsLink || !tabChatLink || !tabSettingsLink) {
    console.error("One or more navigation elements are missing!");
    return;
  }
  if (!loginBtn || !registerBtn) {
    console.error("Authentication buttons are missing!");
    return;
  }
  if (!contactSelect || !messagesDiv || !messageTextInput) {
    console.error("Chat elements are missing!");
    return;
  }
  if (!copyKeyBtn || !cancelAccountBtn) {
    console.error("Settings buttons are missing!");
    return;
  }
  if (!sendMessageBtn) {
    console.error("sendMessageBtn not found in the document.");
  } else {
    sendMessageBtn.disabled = false;
  }

  // ---------------------------
  // Event Listeners
  // ---------------------------
  // Navigation
  tabContactsLink.addEventListener("click", (e) => {
    e.preventDefault();
    setActiveNavLink(tabContactsLink);
    showSection(contactsContainer);
    loadContacts();
  });
  tabChatLink.addEventListener("click", (e) => {
    e.preventDefault();
    setActiveNavLink(tabChatLink);
    showSection(chatContainer);
    populateContactDropdown();
    renderMessages();
  });
  tabSettingsLink.addEventListener("click", (e) => {
    e.preventDefault();
    setActiveNavLink(tabSettingsLink);
    showSection(settingsContainer);
    fetchPublicKey();
  });
  logoutLink.addEventListener("click", (e) => {
    e.preventDefault();
    doLogout();
  });

  // Send Message handler with double encryption + disabling the send button.
  if (sendMessageBtn) {
    sendMessageBtn.addEventListener("click", async function () {
      if (!selectedContact) {
        let recipientInput = prompt("Enter recipient's public key (base64):");
        if (!recipientInput) {
          alert("No recipient provided.");
          return;
        }
        selectedContact = recipientInput;
        let opt = document.createElement("option");
        opt.value = recipientInput;
        opt.textContent = "Unknown user: " + recipientInput;
        contactSelect.appendChild(opt);
        contactSelect.value = recipientInput;
      }
      
      const messageText = messageTextInput.value.trim();
      if (!messageText) return;
      
      try {
        // Disable the send button to avoid duplicates.
        sendMessageBtn.disabled = true;

        if (!oqs) {
          alert("OQS library is still loading. Please try again in a moment.");
          sendMessageBtn.disabled = false;
          return;
        }
        
        // --- Recipient encryption ---
        const recipientPublicKeyBytes = base64ToBytes(selectedContact);
        let kemRecipient;
        let ciphertext, sharedSecret;
        try {
          kemRecipient = new oqs.KeyEncapsulation("Kyber512");
          ({ ciphertext, sharedSecret } = await kemRecipient.encapSecret(recipientPublicKeyBytes));
        } finally {
          if (kemRecipient && kemRecipient.free) {
            kemRecipient.free();
          }
        }
        
        // --- Sender encryption ---
        let kemSender;
        let sender_ciphertext, sender_sharedSecret;
        try {
          kemSender = new oqs.KeyEncapsulation("Kyber512");
          ({ ciphertext: sender_ciphertext, sharedSecret: sender_sharedSecret } =
             await kemSender.encapSecret(base64ToBytes(currentPubKey)));
        } finally {
          if (kemSender && kemSender.free) {
            kemSender.free();
          }
        }
        
        // Validate shared secret lengths.
        if (![16, 24, 32].includes(sharedSecret.length)) {
          throw new Error("Invalid AES key length (recipient): " + sharedSecret.length);
        }
        if (![16, 24, 32].includes(sender_sharedSecret.length)) {
          throw new Error("Invalid AES key length (sender): " + sender_sharedSecret.length);
        }
        
        const recipient_nonce = crypto.getRandomValues(new Uint8Array(12));
        const sender_nonce = crypto.getRandomValues(new Uint8Array(12));
        const ciphertextMsg = await aesGcmEncryptJS(sharedSecret, recipient_nonce, new TextEncoder().encode(messageText));
        const sender_ciphertextMsg = await aesGcmEncryptJS(sender_sharedSecret, sender_nonce, new TextEncoder().encode(messageText));
        
        const res = await fetch("http://127.0.0.1:5000/send_message", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({
            recipient_pubkey: selectedContact,
            // Recipient copy fields
            ciphertext_kem: bytesToBase64(ciphertext),
            ciphertext_msg: bytesToBase64(new Uint8Array(ciphertextMsg)),
            nonce: bytesToBase64(recipient_nonce),
            // Sender copy fields
            sender_ciphertext_kem: bytesToBase64(sender_ciphertext),
            sender_ciphertext_msg: bytesToBase64(new Uint8Array(sender_ciphertextMsg)),
            sender_nonce: bytesToBase64(sender_nonce)
          }),
        });
        
        const data = await res.json();
        if (!data.success) {
          alert("Failed to send message: " + data.error);
          sendMessageBtn.disabled = false;
          return;
        }
        
        messageTextInput.value = "";
        await loadAllMessages();
        contactSelect.value = selectedContact;
        renderMessages();
      } catch (error) {
        console.error("Encryption failed:", error);
        alert("Encryption failed. See console for details.");
      } finally {
        // Re-enable the send button after the attempt is complete.
        sendMessageBtn.disabled = false;
      }
    });
  }
  
  // Authentication
  loginBtn.addEventListener("click", async function () {
    const username = loginUsernameInput.value.trim();
    const password = loginPasswordInput.value.trim();
    const res = await fetch("http://127.0.0.1:5000/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();
    if (!data.success) {
      alert("Login failed: " + data.error);
      return;
    }
    currentUser = username;
    currentPassword = password;
    userLabel.textContent = `Logged in as ${currentUser}`;
    await fetchPublicKey();
    showSection(chatContainer);
    setActiveNavLink(tabChatLink);
    await loadPrivateKey();
    await loadContacts();
    await loadAllMessages();
  });

  registerBtn.addEventListener("click", async function () {
    const username = regUsernameInput.value.trim();
    const password = regPasswordInput.value.trim();
    const res = await fetch("http://127.0.0.1:5000/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();
    if (!data.success) {
      // If the server says "User already exists", show a friendlier message.
      if (data.error && data.error.includes("User already exists")) {
        alert("That username already exists. Please log in or pick a different username.");
      } else {
        alert("Registration failed: " + data.error);
      }
      return;
    }
    alert("Registration successful! You are now logged in.");
    currentUser = username;
    currentPassword = password;
    userLabel.textContent = `Logged in as ${currentUser}`;
    await fetchPublicKey();
    showSection(chatContainer);
    setActiveNavLink(tabChatLink);
    await loadPrivateKey();
    await loadContacts();
    await loadAllMessages();
  });

  // Contacts
  addContactBtn.addEventListener("click", async function () {
    const contact_public_key = contactPublicKeyInput.value.trim();
    const nickname = contactNicknameInput.value.trim();
    if (!contact_public_key || !nickname) {
      alert("Please enter the contact's public key and actual username.");
      return;
    }
    const res = await fetch("http://127.0.0.1:5000/add_contact", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ contact_public_key, nickname })
    });
    const data = await res.json();
    if (data.success) {
      alert("Contact added!");
      contactPublicKeyInput.value = "";
      contactNicknameInput.value = "";
      await loadContacts();
    } else {
      alert("Failed to add contact: " + data.error);
    }
  });

  contactSelect.addEventListener("change", function () {
    selectedContact = contactSelect.value;
    renderMessages();
  });

  // Settings
  copyKeyBtn.addEventListener("click", function () {
    publicKeyDisplay.select();
    document.execCommand("copy");
    alert("Public key copied!");
  });

  cancelAccountBtn.addEventListener("click", async function () {
    if (!confirm("Are you sure you want to delete your account?")) return;
    const res = await fetch("http://127.0.0.1:5000/delete_account", {
      method: "POST",
      credentials: "include"
    });
    const data = await res.json();
    if (data.success) {
      alert("Account deleted!");
      doLogout();
    } else {
      alert("Failed to delete account: " + data.error);
    }
  });

  // ---------------------------
  // Initialize UI
  // ---------------------------
  showSection(authContainer);
  checkSession();

  // ---------------------------
  // Helper Functions
  // ---------------------------
  function showSection(section) {
    authContainer.classList.remove("active");
    contactsContainer.classList.remove("active");
    chatContainer.classList.remove("active");
    settingsContainer.classList.remove("active");
    section.classList.add("active");
  }
  function setActiveNavLink(link) {
    tabContactsLink.classList.remove("active");
    tabChatLink.classList.remove("active");
    tabSettingsLink.classList.remove("active");
    link.classList.add("active");
  }
  async function fetchPublicKey() {
    const res = await fetch("http://127.0.0.1:5000/get_public_key", {
      credentials: "include"
    });
    const data = await res.json();
    if (data.public_key) {
      currentPubKey = data.public_key;
      publicKeyDisplay.value = currentPubKey;
    } else {
      publicKeyDisplay.value = "No public key found.";
    }
  }
  async function loadPrivateKey() {
    const res = await fetch("http://127.0.0.1:5000/get_encrypted_private_key", {
      credentials: "include"
    });
    const data = await res.json();
    if (data.error) {
      console.warn("Error loading encrypted private key:", data.error);
      return;
    }
    const salt = base64ToBytes(data.encrypted_private_key.salt);
    const encKey = base64ToBytes(data.encrypted_private_key.encrypted_key);
    // Use the full salt as IV because the API encrypts using a 16-byte nonce.
    const iv = salt;
    console.log("loadPrivateKey: salt length =", salt.length, "iv length =", iv.length, "ciphertext length =", encKey.length);
  
    try {
      // Attempt to derive and decrypt using the current password
      const derivedKey = await deriveAesKeyFromPassword(currentPassword, salt);
      currentPrivateKey = await aesGcmDecrypt(derivedKey, iv, encKey);
      if (!currentPrivateKey) {
        throw new Error("Decryption returned null, possibly due to an incorrect password.");
      }
      console.log("Private key decrypted:", currentPrivateKey);
    } catch (e) {
      // If decryption fails, prompt the user to enter the password
      alert("Failed to decrypt private key. Please check your password.");
      currentPassword = prompt("Enter your password to unlock your account:");
      if (currentPassword) {
        const derivedKey = await deriveAesKeyFromPassword(currentPassword, salt);
        currentPrivateKey = await aesGcmDecrypt(derivedKey, iv, encKey);
        if (!currentPrivateKey) {
          alert("Decryption failed again. Please try re-logging in.");
        }
      }
    }
  }
  async function deriveAesKeyFromPassword(password, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveBits", "deriveKey"]
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );
  }
  async function aesGcmDecrypt(aesKey, iv, ciphertext) {
    try {
      const plainBuffer = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv, tagLength: 128 },
        aesKey,
        ciphertext
      );
      return new Uint8Array(plainBuffer);
    } catch (e) {
      console.error("AES-GCM decryption failed:", e);
      return null;
    }
  }
  async function aesGcmEncryptJS(keyBytes, ivBytes, plaintext) {
    try {
      if (![16, 24, 32].includes(keyBytes.length)) {
        throw new Error("Invalid AES key length: " + keyBytes.length);
      }
      const key = await crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "AES-GCM" },
        false,
        ["encrypt"]
      );
      const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: ivBytes, tagLength: 128 },
        key,
        plaintext
      );
      return new Uint8Array(ciphertext);
    } catch (error) {
      console.error("AES-GCM encryption failed:", error);
      throw error;
    }
  }
  async function loadContacts() {
    const res = await fetch(`http://127.0.0.1:5000/get_contacts?username=${currentUser}`, {
      credentials: "include"
    });
    const data = await res.json();
    contactsMap = data.contacts || {};
    renderContacts();
  }
  function renderContacts() {
    contactsDiv.innerHTML = "";
    for (const pubKey in contactsMap) {
      const { nickname } = contactsMap[pubKey];
      const div = document.createElement("div");
      div.classList.add("contact-item");
      div.innerHTML = `<span>${nickname}</span>
                       <button class="remove-contact-btn">Remove</button>`;
      div.querySelector(".remove-contact-btn").addEventListener("click", async () => {
        await removeContact(pubKey);
      });
      contactsDiv.appendChild(div);
    }
  }
  async function removeContact(pubKey) {
    const res = await fetch("http://127.0.0.1:5000/remove_contact", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ contact_public_key: pubKey })
    });
    const data = await res.json();
    if (data.success) {
      alert("Contact removed!");
      await loadContacts();
    } else {
      alert("Failed to remove contact: " + data.error);
    }
  }
  async function loadAllMessages() {
    const res = await fetch(`http://127.0.0.1:5000/get_messages?username=${currentUser}`, {
      credentials: "include"
    });
    const data = await res.json();
    allMessages = data.messages || [];
    populateContactDropdown();
    renderMessages();
  }
  function populateContactDropdown() {
    const partners = new Set();
    for (const msg of allMessages) {
      if (msg.sender_pubkey_b64 && msg.sender_pubkey_b64 !== currentPubKey) {
        partners.add(msg.sender_pubkey_b64);
      }
      if (msg.recipient_pubkey_b64 && msg.recipient_pubkey_b64 !== currentPubKey) {
        partners.add(msg.recipient_pubkey_b64);
      }
    }
    for (const pubKey in contactsMap) {
      partners.add(pubKey);
    }
    contactSelect.innerHTML = `<option value="">Select a contact...</option>`;
    for (const partner of partners) {
      let label = partner;
      if (contactsMap[partner] && contactsMap[partner].nickname) {
        label = contactsMap[partner].nickname;
      } else {
        label = `Unknown user: ${partner}`;
      }
      const opt = document.createElement("option");
      opt.value = partner;
      opt.textContent = label;
      contactSelect.appendChild(opt);
    }
    if (selectedContact) {
      contactSelect.value = selectedContact;
    }
  }
  async function renderMessages() {
    messagesDiv.innerHTML = "";
    if (!selectedContact) {
      messagesDiv.innerHTML = "<p>Select a contact to see messages.</p>";
      return;
    }
  
    // 1) Filter messages between you and the selected contact.
    let conversation = allMessages.filter((m) => {
      return (
        (m.sender_pubkey_b64 === selectedContact && m.recipient_pubkey_b64 === currentPubKey) ||
        (m.sender_pubkey_b64 === currentPubKey && m.recipient_pubkey_b64 === selectedContact)
      );
    });
  
    // 2) De-duplicate by message_id.
    const seenIds = new Set();
    const deduped = [];
    for (const msg of conversation) {
      if (!seenIds.has(msg.message_id)) {
        seenIds.add(msg.message_id);
        deduped.push(msg);
      }
    }
  
    // 3) Sort messages by timestamp (oldest first).
    deduped.sort((a, b) => (a.timestamp - b.timestamp));
  
    // 4) Render the deduplicated, sorted messages.
    for (const msg of deduped) {
      const div = document.createElement("div");
      div.classList.add("message");
  
      if (msg.sender_pubkey_b64 === currentPubKey) {
        div.classList.add("sent");
      } else {
        div.classList.add("received");
      }
  
      let text;
      // If the message is from someone else and they are not in your contacts,
      // show a dedicated button to add them.
      if (msg.sender_pubkey_b64 !== currentPubKey && !(msg.sender_pubkey_b64 in contactsMap)) {
        text = "[Message from unknown sender]";
        const addBtn = document.createElement("button");
        addBtn.textContent = "Add Contact";
        addBtn.style.marginLeft = "8px";
        addBtn.addEventListener("click", () => {
          const nickname = prompt("Enter a nickname for this contact:", "New Contact");
          if (nickname) {
            contactPublicKeyInput.value = msg.sender_pubkey_b64;
            contactNicknameInput.value = nickname;
            addContactBtn.click();
          }
        });
        // We'll fill the div with some placeholder text + the button
        div.innerHTML = `<strong>Unknown user: ${msg.sender_pubkey_b64}</strong>: ${text}`;
        div.appendChild(addBtn);
      } else {
        // Attempt to decrypt normally
        text = await decryptPQMessage(msg);
        const senderLabel = msg.sender_pubkey_b64 === currentPubKey
          ? "You"
          : (contactsMap[msg.sender_pubkey_b64]
             ? contactsMap[msg.sender_pubkey_b64].nickname
             : ("Unknown user: " + msg.sender_pubkey_b64));
        div.innerHTML = `<strong>${senderLabel}</strong>: ${text}`;
      }
  
      // Multiply timestamp by 1000 to convert seconds to milliseconds.
      const timeString = new Date(msg.timestamp * 1000).toLocaleString();
      const timeSpan = document.createElement("span");
      timeSpan.classList.add("timestamp");
      timeSpan.textContent = timeString;
      div.appendChild(timeSpan);
  
      messagesDiv.appendChild(div);
    }
  }
  async function decryptPQMessage(msg) {
    if (!oqs) {
      console.warn("OQS library is still loading. Retrying decryption later...");
      return "[Encrypted message]";
    }
    if (!currentPrivateKey || !msg.ciphertext_kem || !msg.ciphertext_msg || !msg.nonce) {
      console.warn("Decryption failed: Missing required parameters.");
      return "[Encrypted message]";
    }
    try {
      const ciphertextKem = base64ToBytes(msg.ciphertext_kem);
      const nonceBytes = base64ToBytes(msg.nonce);
      const ciphertextBytes = base64ToBytes(msg.ciphertext_msg);
  
      console.log("Decrypting message with:", {
        ciphertextKem: bytesToBase64(ciphertextKem),
        nonceBytes: bytesToBase64(nonceBytes),
        ciphertextBytes: bytesToBase64(ciphertextBytes),
      });
  
      let kem;
      let sharedSecret;
      try {
        kem = new oqs.KeyEncapsulation("Kyber512");
        await kem.loadSecretKey(currentPrivateKey);
        sharedSecret = await kem.decapSecret(ciphertextKem);
      } finally {
        if (kem && kem.free) {
          kem.free();
        }
      }
  
      console.log("Derived shared secret:", bytesToBase64(sharedSecret));
  
      const plaintextBuffer = await aesGcmDecryptJS(sharedSecret, nonceBytes, ciphertextBytes);
  
      if (!plaintextBuffer) {
        console.warn("Decryption failed: AES-GCM returned null.");
        return "[Decryption failed]";
      }
  
      return new TextDecoder().decode(plaintextBuffer);
    } catch (err) {
      console.warn("Decapsulation failed:", err);
      return "[Decryption error]";
    }
  }
  async function aesGcmDecryptJS(keyBytes, ivBytes, ciphertext) {
    try {
      if (!keyBytes || !ivBytes || !ciphertext) {
        throw new Error("Decryption failed: Missing key, IV, or ciphertext.");
      }
      if (![16, 24, 32].includes(keyBytes.length)) {
        throw new Error("Invalid AES key length: " + keyBytes.length);
      }
      console.log("AES-GCM Decryption Inputs:", {
        key: bytesToBase64(keyBytes),
        iv: bytesToBase64(ivBytes),
        ciphertext: bytesToBase64(ciphertext),
      });
      const key = await crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
      );
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: ivBytes, tagLength: 128 },
        key,
        ciphertext
      );
      return new Uint8Array(decrypted);
    } catch (e) {
      console.error("AES-GCM decryption failed:", e);
      if (e instanceof DOMException) {
        alert("Decryption failed: Possibly incorrect key, IV, or corrupted ciphertext.");
      }
      return null;
    }
  }
  function base64ToBytes(b64) {
    const binStr = atob(b64.replace(/_/g, "/").replace(/-/g, "+"));
    const bytes = new Uint8Array(binStr.length);
    for (let i = 0; i < binStr.length; i++) {
      bytes[i] = binStr.charCodeAt(i);
    }
    return bytes;
  }
  function bytesToBase64(bytes) {
    let binStr = "";
    for (let i = 0; i < bytes.length; i++) {
      binStr += String.fromCharCode(bytes[i]);
    }
    return btoa(binStr).replace(/\+/g, "-").replace(/\//g, "_");
  }
  async function doLogout() {
    const res = await fetch("http://127.0.0.1:5000/logout", {
      method: "POST",
      credentials: "include"
    });
    await res.json();
    currentUser = null;
    currentPassword = null;
    currentPrivateKey = null;
    currentPubKey = null;
    allMessages = [];
    contactsMap = {};
    selectedContact = null;
    userLabel.textContent = "";
    showSection(authContainer);
    tabContactsLink.classList.remove("active");
    tabChatLink.classList.remove("active");
    tabSettingsLink.classList.remove("active");
  }
  async function checkSession() {
    const res = await fetch("http://127.0.0.1:5000/session_status", {
      credentials: "include"
    });
    const data = await res.json();
    if (data.logged_in) {
      currentUser = data.username;
      userLabel.textContent = `Logged in as ${currentUser}`;
      await fetchPublicKey();
      // Prompt for the password if it is not already set (e.g., after re-opening)
      if (!currentPassword) {
        currentPassword = prompt("Enter your password to unlock your account:");
      }
      await loadPrivateKey();
      await loadContacts();
      await loadAllMessages();
      setActiveNavLink(tabChatLink);
      showSection(chatContainer);
    } else {
      showSection(authContainer);
    }
  }
});
