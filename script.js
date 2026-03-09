// Save and load notes from localStorage
const notesEl = document.getElementById("notes");
const saveBtn = document.getElementById("saveNotes");
const STORAGE_NOTES_KEY = "forensic_lab2_notes";
const STORAGE_CHECK_KEY = "forensic_lab2_checklist";

// Load saved notes
const savedNotes = localStorage.getItem(STORAGE_NOTES_KEY);
if (savedNotes) {
    notesEl.value = savedNotes;
}

// Save notes on button click
saveBtn.addEventListener("click", () => {
    localStorage.setItem(STORAGE_NOTES_KEY, notesEl.value);
    saveBtn.textContent = "Saved!";
    setTimeout(() => (saveBtn.textContent = "Save Notes"), 1000);
});

// Checklist logic
const checkboxes = document.querySelectorAll(".chk");
const progressText = document.getElementById("progressText");
const progressFill = document.getElementById("progressFill");

// Load saved checklist state
const savedChecklist = JSON.parse(localStorage.getItem(STORAGE_CHECK_KEY) || "{}");

checkboxes.forEach((cb) => {
    const id = cb.dataset.id;
    if (savedChecklist[id]) {
        cb.checked = true;
    }
    cb.addEventListener("change", () => {
        savedChecklist[id] = cb.checked;
        localStorage.setItem(STORAGE_CHECK_KEY, JSON.stringify(savedChecklist));
        updateProgress();
    });
});

// Update progress UI
function updateProgress() {
    const total = checkboxes.length;
    let done = 0;
    checkboxes.forEach((cb) => {
        if (cb.checked) done++;
    });
    progressText.textContent = `Progress: ${done} / ${total} tasks completed`;
    const percent = total === 0 ? 0 : (done / total) * 100;
    progressFill.style.width = `${percent}%`;
}

// Initial render
updateProgress();
