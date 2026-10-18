import { dropZoneElement, fileNameElement, logInput } from "./dom.js";
function formatSize(bytes) {
    if (bytes < 1024) {
        return `${bytes} B`;
    }
    if (bytes < 1024 * 1024) {
        return `${(bytes / 1024).toFixed(1)} KB`;
    }
    return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}
function showSelectedFile() {
    const file = logInput.files?.[0];
    if (!file) {
        fileNameElement.textContent = "or drop it here";
        fileNameElement.title = "";
        dropZoneElement.classList.remove("hasFile");
        return;
    }
    fileNameElement.textContent = `${file.name} · ${formatSize(file.size)}`;
    fileNameElement.title = fileNameElement.textContent;
    dropZoneElement.classList.add("hasFile");
}
logInput.addEventListener("change", showSelectedFile);
dropZoneElement.addEventListener("dragover", event => {
    event.preventDefault();
    dropZoneElement.classList.add("dragOver");
});
dropZoneElement.addEventListener("dragleave", () => {
    dropZoneElement.classList.remove("dragOver");
});
dropZoneElement.addEventListener("drop", event => {
    event.preventDefault();
    dropZoneElement.classList.remove("dragOver");
    const files = event.dataTransfer?.files;
    if (!files || files.length === 0) {
        return;
    }
    logInput.files = files;
    logInput.dispatchEvent(new Event("change"));
});
