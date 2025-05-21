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
  - Modular OS fingerprinting pipeline
  - Flexible analysis capabilities
  - JSON-based data export
- **Target Users**: organization IT administrator
- **Key Differentiators**:
  - The data source is VLAN trunk packet capturing. unicast flood/multicast/broadcast packet are target
  - Modular analysis pipeline with specialized detection methods
  - Shell integration for flexible analysis
  - Very scalable. Avoiding main stream capture, it need only usual server resource for large number of PC/Macs. e.g., 10GB DB to 30000 PC/Macs.
  - Near realtime detection
  - Continuous monitor
- **Technical Architecture**:
  - Consists of three parts:
    - Monitoring daemon: Captures and stores fingerprints in LMDB
    - Data export: Streams JSON data from LMDB
    - Analysis pipeline: Modular analysis tools with shell integration
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
  - Linux CLI with shell integration
- **Output**:
  - JSON stream format
  - Shell-friendly for analysis

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
  - jq for JSON processing
  - Shell tools for analysis
- **Performance Requirements**:
  - Random MAC expiration: 24 hours of no detection
  - LMDB memory size: Currently using 10GB for ~30,000 devices
  - Expected device purpose based on OUI analysis
  - Streaming processing for memory efficiency
- **Security Requirements**:
  - Requires sudo for packet capture
  - Network security considerations are the responsibility of the deploying organization
- **Scalability Considerations**:
  - CPU and usable memory
  - No VLAN range restrictions
  - Parallel processing support

## 7. Non-Functional Requirements
- **Performance Metrics**: 
  - JSON processing speed
  - Analysis pipeline throughput
  - Memory usage per analysis module
- **Reliability Requirements**: 
  - Error handling in each analysis module
  - Data preservation on analysis failure
- **Security Requirements**: 
  - Secure handling of network data
  - Proper error logging
- **Compliance Requirements**: 
  - Network monitoring compliance
  - Data retention policies

## 8. Development Guidelines
- **Coding Standards**: 
  - Modular design
  - Stream processing
  - Error handling
  - Documentation
- **Version Control**: Git
- **Testing Requirements**: 
  - Unit tests for each module
  - Pipeline integration tests
  - Performance tests
- **Documentation Requirements**: 
  - Module specifications
  - Pipeline usage
  - Shell integration guide

## 9. Timeline and Milestones
- **Development Phases**: 
  1. Core capture and storage
  2. Basic analysis modules
  3. Shell integration
  4. Advanced analysis
- **Key Deliverables**: 
  - Capture daemon
  - Analysis modules
  - Documentation
- **Dependencies**: 
  - p0f signatures
  - OUI database
  - Fingerbank database
- **Risk Assessment**: 
  - Analysis accuracy
  - Performance impact
  - Resource usage

## 10. Success Criteria
- **Key Performance Indicators**: 
  - Detection accuracy
  - Processing speed
  - Resource usage
- **Metrics for Success**: 
  - 70% detection rate
  - Real-time processing
  - Low resource usage
- **Validation Methods**: 
  - Known device testing
  - Performance benchmarking
  - Accuracy measurement

## 11. Future Considerations
- **Potential Future Features**: 
  - Additional analysis modules
  - Web interface
  - API integration
- **Scalability Plans**: 
  - Distributed processing
  - Cloud integration
- **Maintenance Requirements**: 
  - Regular signature updates
  - Performance monitoring
  - Error tracking 