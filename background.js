// Listen for messages from other parts of the extension
console.log("Background script loaded and active.");

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    console.log("Message received in background:", message);

    if (message.type === "test") {
        sendResponse({ reply: "Hello from background script!" });
    }

    return true; // Required for async responses
});
