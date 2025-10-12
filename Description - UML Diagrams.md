### **1. Package Diagram Explanation**

The package diagram illustrates the high-level structure of the Configuration Drift Detection System and how its major modules interact with each other. The system is divided into several logical packages, each representing a key functional area. The **User Interface Module** acts as the entry point where users interact through login, dashboards, and data visualization components. It connects with other modules such as the **Configuration Parser Module** for reading and storing configuration data, and the **Drift Comparison Module** for identifying differences between configurations.

The **Risk Scoring Module** evaluates detected differences by assigning risk values and providing root cause insights. The **Visualization Module** handles graphical representations like heatmaps and trend graphs to make complex drift data easily understandable. The **Remediation Planner Module** manages corrective actions through task prioritization and progress tracking. The **Notification Module** ensures timely alerts and activity logging, while the **Security Module** provides authentication, encryption, and role-based access control. Together, these packages ensure that the system operates securely, transparently, and efficiently from data ingestion to analysis and remediation.

---

### **2. Object Diagram Explanation**

The object diagram represents a snapshot of system instances at runtime, showing how data flows between key entities. Here, a **User** instance named “admin” is associated with a **Role** instance (“SysAdmin”) defining permissions for configuration management and report viewing. Two **ConfigurationFile** objects, representing the baseline and current configurations, are linked to a **DriftComparison** instance that identifies deviations between them.

Each drift is detailed through **Difference** objects, which include attributes such as type, description, and associated risk scores. These differences trigger a **Notification** instance that alerts users about high-risk drifts. Additionally, a **RemediationTask** instance is generated to address a detected issue, indicating its description, priority, and estimated completion time. The **Visualization** object connects to the drift comparison to render visual insights such as heatmaps. This diagram shows how live data entities relate and collaborate to provide end-to-end configuration drift detection, scoring, alerting, and visualization.

---

### **3. Class Diagram Explanation**

The class diagram defines the static structure of the system, detailing classes, attributes, methods, and relationships. The **User** class handles authentication, account management, and activity tracking, while the **Role** class supports access control through assigned permissions. The **ConfigurationFile** class manages configuration uploads, parsing, and validation. The **DriftComparison** class performs the comparison between baseline and current configurations, identifies differences, filters results, and calculates risk scores.

The **Difference** class stores details about configuration changes and potential root causes. The **Notification** class manages alert generation and delivery to users based on drift severity. The **RemediationTask** class is responsible for creating and tracking corrective actions, while the **Visualization** class generates visual elements like heatmaps and trend graphs for reporting and monitoring. Relationships between these classes demonstrate clear dependencies: users are linked to roles and tasks, comparisons are linked to configuration files and differences, and visualizations depend on drift data. Overall, the class structure ensures modularity, scalability, and efficient data handling.

---

### **4. Use Case Diagram Explanation**

The use case diagram presents the functional behavior of the system as perceived by different actors. The primary actors include the **System Administrator**, **Security Analyst**, and **IT Team Manager**. The System Administrator is responsible for logging in, managing user accounts, uploading configurations, and initiating drift analysis. The Security Analyst focuses on analyzing visualized drifts, viewing risk scores, and receiving notifications for high-risk anomalies. The IT Team Manager oversees remediation planning, task tracking, and generating reports for long-term monitoring.

The diagram also includes an extension scenario for handling invalid uploads when the uploaded file format is incorrect. Each use case is accompanied by notes describing prerequisites and outcomes—for instance, administrators must be logged in to manage accounts or upload configurations. These use cases collectively represent how the system’s features are used to detect, analyze, visualize, and remediate configuration drifts across multiple organizational roles.

---

### **5. Activity Diagram Explanation**

The activity diagram captures the dynamic workflow of the Configuration Drift Detection System from the perspective of its key users. The process begins when users log in, after which multiple concurrent activities occur. The **System Administrator** manages user accounts, uploads configuration files, compares configurations, and handles invalid uploads. The administrator also plans remediation tasks and monitors system dashboards.

The **Security Analyst** focuses on analyzing drift results, viewing heatmaps, recalculating risk scores, and checking for high-risk alerts. This branch shows how conditional paths are handled — for example, notifications are sent only when drift risk exceeds a threshold. The **IT Team Manager** manages and tracks remediation tasks, assigns responsibilities, monitors completion times, and generates summary reports. The diagram also highlights collaboration points between roles, such as when the administrator tags drift items that the IT manager later prioritizes for remediation. This workflow ensures that detection, analysis, and resolution activities are coordinated seamlessly across teams.

---

**In summary**, these UML diagrams collectively describe both the **static and dynamic architecture** of the Configuration Drift Detection System. They provide a complete implementation-level perspective—from package organization and class structures to object instances, user interactions, and activity flows—demonstrating how all modules and actors work together to ensure effective drift detection, visualization, and remediation management.
