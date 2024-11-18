# Compliance Framework Plugin Template

This is a template for building a compliance framework plugin.

Inspect main.go for a detailed description of how to build the plugin.

## Prerequisites

* GoReleaser https://goreleaser.com/install/

## Building

Once you are ready to serve the plugin, you need to build the binaries which can be used by the agent.

```shell
goreleaser release --snapshot --clean
```

## Usage

You can use this plugin by passing it to the compliiance agent

```shell
agent --plugin=[PATH_TO_YOUR_BINARY]
```

## Releasing

Once you are ready to release your plugin, you need only create a release in Github, and the plugin binaries
will be added as artifacts on the release page

## Process

The process follows the methodology in https://avleonov.com/2022/10/04/how-to-perform-a-free-ubuntu-vulnerability-scan-with-openscap-and-canonicals-official-oval-content/

1. Install oscap (and bunzip2) for scanning and unzipping respectively
2. Grab the OVAL data at https://security-metadata.canonical.com/oval/com.ubuntu.<release>.usn.oval.xml.bz2 and unzip it
3. Perform an oscap scan and output the results to the desired location
4. Process the results into a format for the policies
5. Check the results against the policies for violations, and send findings and observations

## Testing

Some of the tests can only be ran within a docker container running Ubuntu

To run these locally, run
`make up` and `make test`
