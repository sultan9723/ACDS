// MongoDB initialization script for ACDS
// This script runs when the container is first created

// Create the database and collections
db = db.getSiblingDB("acds");

// Create collections with indexes
db.createCollection("users");
db.createCollection("threats");
db.createCollection("email_scans");
db.createCollection("feedback");
db.createCollection("alerts");
db.createCollection("audit_logs");
db.createCollection("reports");
db.createCollection("system_stats");

// Create indexes for users
db.users.createIndex({ email: 1 }, { unique: true });
db.users.createIndex({ role: 1 });
db.users.createIndex({ is_active: 1 });

// Create indexes for threats
db.threats.createIndex({ threat_id: 1 }, { unique: true });
db.threats.createIndex({ severity: 1 });
db.threats.createIndex({ status: 1 });
db.threats.createIndex({ detected_at: -1 });
db.threats.createIndex({ threat_type: 1 });
db.threats.createIndex({ email_sender: 1 });

// Create indexes for email_scans
db.email_scans.createIndex({ scan_id: 1 }, { unique: true });
db.email_scans.createIndex({ is_phishing: 1 });
db.email_scans.createIndex({ scanned_at: -1 });
db.email_scans.createIndex({ email_sender: 1 });

// Create indexes for feedback
db.feedback.createIndex({ feedback_id: 1 }, { unique: true });
db.feedback.createIndex({ is_reviewed: 1 });
db.feedback.createIndex({ feedback_type: 1 });
db.feedback.createIndex({ submitted_at: -1 });

// Create indexes for alerts
db.alerts.createIndex({ alert_id: 1 }, { unique: true });
db.alerts.createIndex({ is_acknowledged: 1 });
db.alerts.createIndex({ severity: 1 });
db.alerts.createIndex({ created_at: -1 });

// Create indexes for audit_logs
db.audit_logs.createIndex({ timestamp: -1 });
db.audit_logs.createIndex({ user_id: 1 });
db.audit_logs.createIndex({ action_type: 1 });

// Create indexes for system_stats
db.system_stats.createIndex({ recorded_at: -1 });
db.system_stats.createIndex({ period: 1 });

print("ACDS MongoDB initialized successfully");
print(
  "Collections created: users, threats, email_scans, feedback, alerts, audit_logs, reports, system_stats"
);
print("Indexes created for all collections");
print("Admin users must be provisioned through backend bootstrap or the user management API");

