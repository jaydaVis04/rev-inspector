const uploadForm = document.querySelector("#upload-form");
const fileInput = document.querySelector("#file");
const dropZone = document.querySelector(".drop-zone");
const uploadState = document.querySelector("#upload-state");
const selectedFile = document.querySelector("#selected-file");
const selectedSize = document.querySelector("#selected-size");
const progressFill = document.querySelector("#progress-fill");
const progressLabel = document.querySelector("#progress-label");
const notes = document.querySelector("#analyst-notes");

function formatBytes(bytes) {
  if (!bytes) return "0 bytes";
  const units = ["bytes", "KiB", "MiB", "GiB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / Math.pow(1024, index);
  return `${value.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

function showUploadState(file) {
  if (!uploadState || !file) return;
  selectedFile.textContent = file.name;
  selectedSize.textContent = formatBytes(file.size);
  progressFill.style.width = "0%";
  progressLabel.textContent = "Preparing upload...";
  uploadState.hidden = false;
}

if (fileInput) {
  fileInput.addEventListener("change", () => showUploadState(fileInput.files[0]));
}

if (dropZone && fileInput) {
  ["dragenter", "dragover"].forEach((eventName) => {
    dropZone.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropZone.classList.add("dragover");
    });
  });

  ["dragleave", "drop"].forEach((eventName) => {
    dropZone.addEventListener(eventName, () => dropZone.classList.remove("dragover"));
  });

  dropZone.addEventListener("drop", (event) => {
    event.preventDefault();
    if (event.dataTransfer.files.length) {
      fileInput.files = event.dataTransfer.files;
      showUploadState(fileInput.files[0]);
    }
  });
}

if (uploadForm) {
  uploadForm.addEventListener("submit", (event) => {
    const file = fileInput.files[0];
    if (!file || !window.XMLHttpRequest) return;

    event.preventDefault();
    showUploadState(file);

    const request = new XMLHttpRequest();
    request.open("POST", uploadForm.action);

    request.upload.addEventListener("progress", (event) => {
      if (!event.lengthComputable) return;
      const percent = Math.round((event.loaded / event.total) * 100);
      progressFill.style.width = `${percent}%`;
      progressLabel.textContent = percent < 100 ? `${percent}% — Uploading sample...` : "Upload complete — analyzing file...";
    });

    request.addEventListener("load", () => {
      progressFill.style.width = "100%";
      progressLabel.textContent = "Generating report...";
      document.open();
      document.write(request.responseText);
      document.close();
    });

    request.addEventListener("error", () => {
      progressLabel.textContent = "Analysis failed — request did not complete.";
    });

    request.send(new FormData(uploadForm));
  });
}

if (notes) {
  const key = notes.dataset.notesKey;
  notes.value = localStorage.getItem(key) || "";
  notes.addEventListener("input", () => localStorage.setItem(key, notes.value));
}
