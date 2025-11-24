# Review Lite

Review Lite is a lightweight, single-file Review and Scoring System built with **Flask** (Python) and **Vue.js**.

It allows administrators to manage candidates (entities), upload attachments (PDF, DOCX, etc.), and manage reviewers. Reviewers can log in, view candidates, preview documents online, and submit scores.

## Features

* **Single File Deployment:** The backend logic and frontend template are contained within a single `.py` file for extreme portability.
* **Role-Based Access Control:**
    * **Admin:** Manage candidates, upload files, manage reviewer accounts, control scoring phases, export results to Excel.
    * **Reviewer:** View candidates, preview attachments, submit scores (Interview & Summary).
* **Document Preview:** Supports online preview for PDF, Images, DOCX, and XLSX files.
* **Blind Review Mode:** Admins can toggle "Blind Mode" which anonymizes candidate names and filenames for reviewers.
* **Scoring Controls:** Admins can lock/unlock specific scoring channels (e.g., Interview Score or Summary Score).
* **Excel Export:** One-click export of all scores.

## Requirements

* Python 3.x
* Flask
* Werkzeug

## Installation

1.  **Install Dependencies:**
    ```bash
    pip install flask
    ```

2.  **Run the Application:**
    ```bash
    python app.py
    ```

3.  **Access the System:**
    Open your browser and go to: `http://localhost:5000`

## Default Accounts

The system automatically initializes with the following accounts upon the first run:

### Administrator
* **Username:** `admin`
* **Password:** `admin`

### Reviewers
* **Usernames:** `r1`, `r2`, `r3`
* **Password:** `123`

*(Note: Admins can add or delete reviewers directly from the dashboard)*

## Usage Guide

1.  **Login as Admin:** Use the default admin credentials.
2.  **Add Candidates:** Click "+ Add Entity" to create a candidate and upload their resume/documents.
3.  **Distribute Accounts:** Give reviewer credentials to your team.
4.  **Review Process:** Reviewers log in, click file names to preview them, and enter scores.
5.  **Monitor & Export:** The Admin can see who has reviewed whom in real-time and export the final data to CSV/Excel.

## Notes

* **Database:** A SQLite database (`review_system.db`) will be created automatically in the same directory.
* **Uploads:** Uploaded files are stored in the `uploads/` folder.
* **Security:** This is a "Lite" demo system. For production use, please change the `app.secret_key` in the code.