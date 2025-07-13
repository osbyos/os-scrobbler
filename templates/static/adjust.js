// static/adjust.js
function adjustTimestamps() {
  const rows = document.querySelectorAll("#track-table tr");
  const offset = parseInt(document.getElementById("offset").value);
  rows.forEach(row => {
    const tsCell = row.querySelector("td[data-timestamp]");
    const adjCell = row.querySelector(".adjusted");
    if (tsCell && adjCell) {
      const unix = parseInt(tsCell.dataset.timestamp) + offset * 3600;
      const date = new Date(unix * 1000);
      adjCell.textContent = date.toLocaleString();
    }
  });
}

function submitScrobbles() {
  alert("TODO: send adjusted data to server via POST");
  // future: use fetch() to post adjusted entries for upload
}
