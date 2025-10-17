-- ================== ALERTS TABLE ==================
IF NOT EXISTS (SELECT * FROM sys.objects WHERE name = 'Alerts' AND type = 'U')
BEGIN
    CREATE TABLE Alerts (
        Id INT IDENTITY(1,1) PRIMARY KEY,
        Timestamp DATETIME DEFAULT GETDATE(),
        SrcIP NVARCHAR(50) NOT NULL,
        DstIP NVARCHAR(50),
        Protocol NVARCHAR(20),
        SrcPort INT NULL,
        DstPort INT NULL,
        AttackType NVARCHAR(50),           -- Port Scan, Flood, Brute Force
        Severity NVARCHAR(20),             -- LOW, MEDIUM, HIGH, CRITICAL
        Description NVARCHAR(255),
        PacketCount INT DEFAULT 1,
        ExtraInfo NVARCHAR(255) NULL
    );
    CREATE INDEX IX_Alerts_Timestamp ON Alerts(Timestamp);
    CREATE INDEX IX_Alerts_SrcIP ON Alerts(SrcIP);
END
GO

-- ================== TRAFFIC TABLE ==================
IF NOT EXISTS (SELECT * FROM sys.objects WHERE name = 'Traffic' AND type = 'U')
BEGIN
    CREATE TABLE Traffic (
        Id INT IDENTITY(1,1) PRIMARY KEY,
        Timestamp DATETIME DEFAULT GETDATE(),
        SrcIP NVARCHAR(50),
        DstIP NVARCHAR(50),
        Protocol NVARCHAR(20),
        SrcPort INT NULL,
        DstPort INT NULL,
        PacketCount INT DEFAULT 1,
        Info NVARCHAR(255)
    );
    CREATE INDEX IX_Traffic_Timestamp ON Traffic(Timestamp);
    CREATE INDEX IX_Traffic_SrcIP ON Traffic(SrcIP);
END
GO
