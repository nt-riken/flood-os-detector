# Flood OS Detector - Product Requirements Document

## 1. Executive Summary
- **Project Name**: Flood OS Detector
- **Purpose**: Network traffic analysis tool for OS detection
- **Key Stakeholders**: Primary developer and organization IT administrators
- **High-level Goals**: Do best guess of used OS type in an organization
- **Success Metrics**: Success to guess 70% of monitored MAC addresses within 24 hours of initial detection

## 2. Problem Statement
- **Current Challenges**: 
  - Establish a method of determining OS type
  - Continuous running architecture
  - Undetermined handling of Random MAC addresses
- **Pain Points**: 
  - Many fragmented methods are recommended
  - Random MAC address handling needs improvement
- **Solution Need**: 
  - Effective methods determining OS type (as detailed in Technical Architecture)
  - Effective garbage collection method for expired entries

## 3. Product Overview
- **Core Features**:
  - Network packet capture
  - OS fingerprinting
  - Traffic analysis
  - Data export capabilities
- **Target Users**: organization IT administrator
- **Key Differentiators**:
  - The data source is VLAN trunk packet capturing. unicast flood/multicast/broadcast packet are target
  - Mix of methods to detect OS. p0f TCP Syn analyze and DHCP/mDNS/SSDP analysis.
  - Very scalable. Avoiding main stream capture, it need only usual server resource for large number of PC/Macs. e.g., 10GB DB to 30000 PC/Macs.
  - Near realtime detection
  - Continuous monitor
- **Technical Architecture**:
  - Consists of two parts:
    - Monitoring daemon: Captures and stores fingerprints in LMDB
    - Analyze tool: Reads LMDB and outputs detection results
  - Uses LMDB as an in-memory database for performance and persistence

## 4. User Stories
- **Primary User Personas and Use Cases**:
  - Security Analyst: Grasp vulnerable candidate devices as Attack Surface Management
  - Network Administator: Understand distribution of deployed OS for future plan, check illegal devices for administration point of view
  - IT support: Understand majority of deployed OS and make answer quality higher, etc

## 5. Functional Requirements
- **Data source network and NIC**:
  - trunk VLAN interface that can capture as wide an area as possible. No filtering.
  - 2 NIC server. 1 for capture and 1 for remote-access. 1GE is enough for both.
- **OS**:
  - Linux with packet capture access right
  - Tested on AlmaLinux
- **User Interface**:
  - Linux CLI
- **Output**:
  - CSV

## 6. Technical Requirements
- **Development Environment**:
  - Python-based
  - Cursor IDE
  - uv (REQUIRED) for package management
- **Technology Stack**:
  - scapy module for capturing/packet analysis
  - LMDB as memory DB
  - p0f (using fp file in p0f)
  - nmap (using OUI file in nmap)
- **Performance Requirements**:
  - Random MAC expiration: 24 hours of no detection
  - LMDB memory size: Currently using 10GB for ~30,000 devices
  - Expected device purpose based on OUI analysis
- **Security Requirements**:
  - Requires sudo for packet capture
  - Network security considerations are the responsibility of the deploying organization
- **Scalability Considerations**:
  - CPU and usable memory
  - No VLAN range restrictions

## 7. Non-Functional Requirements
- **Performance Metrics**: [To be filled]
- **Reliability Requirements**: [To be filled]
- **Security Requirements**: [To be filled]
- **Compliance Requirements**: [To be filled]

## 8. Development Guidelines
- **Coding Standards**: [To be filled]
- **Version Control**: Git
- **Testing Requirements**: [To be filled]
- **Documentation Requirements**: [To be filled]

## 9. Timeline and Milestones
- **Development Phases**: [To be filled]
- **Key Deliverables**: [To be filled]
- **Dependencies**: [To be filled]
- **Risk Assessment**: [To be filled]

## 10. Success Criteria
- **Key Performance Indicators**: [To be filled]
- **Metrics for Success**: [To be filled]
- **Validation Methods**: [To be filled]

## 11. Future Considerations
- **Potential Future Features**: [To be filled]
- **Scalability Plans**: [To be filled]
- **Maintenance Requirements**: [To be filled] 