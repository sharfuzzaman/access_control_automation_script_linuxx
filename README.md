# Linux Access Control Management System

This repository provides an automated shell script solution (`access_control_linux.sh`) for managing complex user hierarchies and system access controls. It is designed to streamline the configuration of user accounts and organizational structures based on customizable input files.

> [!CAUTION]
> **PRECAUTIONARY NOTE:** This script performs high-level system modifications (users, groups, and permissions). **Run this script only within a laboratory or Virtual Machine (VM) environment.** A rollback/revert utility is currently in development; until its release, changes made by this script must be undone manually.

---

## 📋 Prerequisites

* **Environment:** Linux-based OS (Debian based distribution such as Debain/Fedora/Linux Mint recommended in a VM).
* **Privileges:** Root or sudo access is required for execution.

## ⚙️ Configuration

Before execution, you must tailor the configuration files to your specific environment:

### 1. User Definition (`users_lists`)
Edit the `users_lists` file to include the specific usernames required for your organization.

### 2. Script Customization (`access_control_linux.sh`)
* **Organizational Hierarchy:** Open the script and modify the department/management names to match your corporate structure.
* **Security Credentials:** Locate the `myPassword` section within the script and input the root user password. 
  * *Note: A more secure credential handling method is planned for 2026 updates.*

---

## 🚀 Installation & Usage

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/sharfuzzaman/linux-rbac-automation.git
   cd linux-rbac-automation
   ```
2. **Set Executable Permissions:**
    ```bash
    sudo chmod +x access_control_linux.sh
3. **Execute the Script**
    ```bash
    ./access_control_linux.sh
## 📩 Support & Contact
If you encounter technical difficulties or bugs:
* **GitHub Issues:** Open a comment or issue in this repository.
* **Email Support:** Leave your contact email in a comment; the expected response time is within 24 hours.

  
