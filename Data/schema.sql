-- ================== ALERTS TABLE ==================
IF NOT EXISTS (SELECT * FROM sys.objects WHERE name = 'Alerts' AND type = 'U')
BEGIN
    CREATE TABLE Alerts (
        Id INT IDENTITY(1,1) PRIMARY KEY,
        Timestamp DATETIME DEFAULT GETDATE(),
        SrcIP NVARCHAR(50),
        DstIP NVARCHAR(50),
        Protocol NVARCHAR(20),
        AttackType NVARCHAR(50),       -- loại tấn công (Port Scan, Flood, v.v.)
        Severity NVARCHAR(20),         -- mức độ (Low, Medium, High)
        Description NVARCHAR(255)
    )
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
        Info NVARCHAR(255),
        PacketCount INT DEFAULT 1       -- số lượng packet
    )
END
GO
