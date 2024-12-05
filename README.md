# Syft Packages Extractor

This package is designed to analyze container images and extract package information using the Syft tool.

## Table of Contents
1. [Overview](#overview)
2. [Features](#features)
3. [Installation](#installation)
4. [Usage](#usage)
5. [Contributing](#contributing)
6. [License](#license)

## Overview

The Syft Packages Extractor analyzes container images to extract detailed package information. It uses the Syft tool to examine images and provides information on the packages found within those images.

## Features

- Analyze container images and extract package information.
- Handle multiple image formats and locations.
- Log the analysis process and results.

## Installation

To install this package, you need to have [Go](https://golang.org/doc/install) installed on your machine.

1. Clone the repository:
    ```sh
    git clone https://github.com/Checkmarx/containers-syft-package-extractor.git
    ```

2. Navigate to the project directory:
    ```sh
    cd containers-syft-package-extractor
    ```

3. Install dependencies:
    ```sh
    go mod tidy
    ```

## Usage

Here is an example of how to use the `SyftPackagesExtractor`:

```go
package main

import (
    "github.com/Checkmarx/containers-types/types"
    "github.com/Checkmarx/containers-syft-package-extractor/syftPackagesExtractor"
    "log"
)

func main() {
    extractor := syftPackagesExtractor.SyftPackagesExtractor{}

    images := []types.ImageModel{
        // Populate with ImageModel objects
    }

    // Analyze images
    containerResolution, err := extractor.AnalyzeImages(images)
    if err != nil {
        log.Fatalf("Error analyzing images: %v", err)
    }

    // Handle the container resolution as needed
    log.Printf("Analyzed images: %v", containerResolution)
}
