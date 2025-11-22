# Management API Documentation

Welcome to the InferaDB Management API documentation. This directory contains comprehensive guides for integrating, deploying, and operating the Management API.

## New to Management API?

Start here: **[Getting Started Guide](GettingStarted.md)** - Step-by-step tutorial for setting up your first Management API instance and making your first API calls.

## Quick Reference

- **[OpenAPI Specification](../OpenAPI.yaml)** - Complete REST API reference with all endpoints, request/response schemas
- **[Examples](Examples.md)** - Real-world code examples and integration patterns

## Core Documentation

### System Architecture

- **[Overview](Overview.md)** - Complete entity definitions, data model, relationships, and behavioral rules
  - ⚠️ _Note: This is a large file (5,000+ lines). Use your editor's search function or the table of contents to navigate._
- **[Architecture](Architecture.md)** - System architecture diagrams showing component layers and deployment topologies
- **[Data Flows](Flows.md)** - Detailed sequence diagrams for user registration, login, token generation, and org setup

### Authentication & Security

- **[Authentication](Authentication.md)** - Complete authentication documentation covering:
  - Two-token architecture (session tokens + vault JWTs)
  - Authentication methods (password, passkey, OAuth, client assertion)
  - JWT claims structure and token validation
  - Security considerations and best practices

### API Features

- **[Pagination](Pagination.md)** - List endpoint pagination specification

  - Offset-based pagination
  - Query parameters and response format
  - Performance considerations

- **[Audit Logs](AuditLogs.md)** - Security audit trail and compliance
  - Event types (auth, user mgmt, organization, vault, client)
  - Event severity levels
  - Querying and filtering
  - Compliance reporting examples

## Operations

### Deployment & Performance

- **[Deployment Guide](Deployment.md)** - Production deployment guide

  - Single-instance and multi-instance (HA) setup
  - Kubernetes configuration examples
  - Health checks and graceful shutdown
  - Security best practices

- **[Performance Benchmarks](Performance.md)** - Performance and optimization
  - Latency characteristics (p50/p95/p99)
  - Throughput benchmarks (RPS)
  - Scalability guidelines
  - Tuning parameters

### Troubleshooting

- **[Troubleshooting Guide](Troubleshooting.md)** - Common issues and solutions
  - Installation and setup issues
  - Database/storage problems
  - Authentication failures
  - API errors
  - Performance issues
  - Deployment problems

## Development

- **[Contributing Guide](../CONTRIBUTING.md)** - Development workflow and contribution guidelines
  - Code style standards
  - Testing practices
  - Commit message format
  - Pull request process

## Additional Resources

### Load Testing

- **[Load Testing Suite](../loadtests/)** - k6-based load testing
  - Test scenarios (auth, vaults, organizations, spike)
  - Running tests and interpreting results
  - CI/CD integration

### Testing Infrastructure

- **[FoundationDB Integration Tests](../docker/fdb-integration-tests/)** - Docker-based FDB test environment
  - Quick start and architecture
  - Environment variables
  - Troubleshooting

## Documentation Roadmap

Planned documentation (not yet available):

- **Authorization Guide** - Vault access control, role-based permissions, and policy integration
- **Migration Guide** - Database schema changes and upgrade procedures
- **Backup & Restore** - Disaster recovery procedures
- **SDK Documentation** - Language-specific client libraries (when available)

## Need Help?

- **Issues**: [github.com/inferadb/inferadb/issues](https://github.com/inferadb/inferadb/issues)
- **Documentation**: [inferadb.com/docs](https://inferadb.com/docs)
- **Security**: [security@inferadb.com](mailto:security@inferadb.com)
