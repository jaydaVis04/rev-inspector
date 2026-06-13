const uploadForm = document.querySelector("#upload-form");
const fileInput = document.querySelector("#file");
const dropZone = document.querySelector(".drop-zone");
const uploadState = document.querySelector("#upload-state");
const selectedFile = document.querySelector("#selected-file");
const selectedSize = document.querySelector("#selected-size");
const progressFill = document.querySelector("#progress-fill");
const progressLabel = document.querySelector("#progress-label");
const fileName = document.querySelector("#file-name");
const notes = document.querySelector("#analyst-notes");
const navItems = Array.from(document.querySelectorAll(".nav-item[href^='#']"));
const copyButtons = Array.from(document.querySelectorAll("[data-copy]"));
let manualNavActiveUntil = 0;

function formatBytes(bytes) {
  if (!bytes) return "0 bytes";
  const units = ["bytes", "KiB", "MiB", "GiB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / Math.pow(1024, index);
  return `${value.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

function showUploadState(file) {
  if (!file) return;
  if (fileName) fileName.textContent = `${file.name} (${formatBytes(file.size)})`;
  if (uploadState) {
    selectedFile.textContent = file.name;
    selectedSize.textContent = formatBytes(file.size);
    progressFill.style.width = "0%";
    progressLabel.textContent = "Preparing upload...";
    uploadState.hidden = false;
  }
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

copyButtons.forEach((button) => {
  button.addEventListener("click", async () => {
    const value = button.dataset.copy || "";
    if (!value) return;

    try {
      await navigator.clipboard.writeText(value);
      button.textContent = "Copied";
      setTimeout(() => {
        button.textContent = "Copy";
      }, 1400);
    } catch {
      button.textContent = "Copy failed";
      setTimeout(() => {
        button.textContent = "Copy";
      }, 1800);
    }
  });
});

function setActiveNav(hash) {
  navItems.forEach((item) => {
    item.classList.toggle("active", item.getAttribute("href") === hash);
  });
}

if (navItems.length) {
  navItems.forEach((item) => {
    item.addEventListener("click", () => {
      manualNavActiveUntil = Date.now() + 1200;
      setActiveNav(item.getAttribute("href"));
    });
  });

  const observedSections = navItems
    .map((item) => document.querySelector(item.getAttribute("href")))
    .filter(Boolean);

  const observer = new IntersectionObserver(
    (entries) => {
      if (Date.now() < manualNavActiveUntil) return;

      const visible = entries
        .filter((entry) => entry.isIntersecting)
        .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];

      if (visible) {
        setActiveNav(`#${visible.target.id}`);
      }
    },
    {
      rootMargin: "-96px 0px -55% 0px",
      threshold: [0.15, 0.35, 0.6],
    },
  );

  observedSections.forEach((section) => observer.observe(section));

  if (window.location.hash) {
    manualNavActiveUntil = Date.now() + 1200;
    setActiveNav(window.location.hash);
  }

  window.addEventListener("hashchange", () => {
    manualNavActiveUntil = Date.now() + 1200;
    setActiveNav(window.location.hash);
  });
}
