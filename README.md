# DrvDetect

DrvDetect is a Windows prototype for early detection of suspicious driver-loading activity. The project monitors low-level system events related to process creation, kernel image loading, and registry modifications in order to identify potentially dangerous or unauthorized driver-loading scenarios.

## Overview

The project consists of two components:

- `km` — a kernel-mode driver responsible for event monitoring and partial blocking.
- `um` — a user-mode console application that receives alerts from the driver and displays them.

The main idea is to detect suspicious behavior before a dangerous driver is fully loaded into the kernel.

## How It Works

The kernel-mode driver registers callbacks for process creation, kernel image loading, and registry modifications.

It analyzes these events and looks for suspicious patterns such as:

- execution of low-level helper tools;
- modification of driver service configuration in the Windows registry;
- suspicious `ImagePath` values for driver services;
- loading of potentially unsafe kernel modules;
- attempts to weaken Windows protection mechanisms related to vulnerable drivers.

When a suspicious event is detected, the driver either logs an alert or blocks the action. Alerts are stored in an internal ring buffer.

The user-mode application connects to `\\\\.\\DrvDetect`, requests alerts via `IOCTL`, and prints them to the console.

## Architecture

- `km/` — kernel-mode monitoring driver
- `um/` — user-mode alert reader
- shared alert structure and `IOCTL` interface are defined in the shared headers

## Purpose

DrvDetect is a research and educational prototype focused on low-level monitoring of Windows driver-loading behavior. It is not a full EDR or antivirus product, but a specialized tool for studying and detecting suspicious kernel-related activity.

## Notes

The current implementation is a prototype with rule-based detection logic and can be extended with additional indicators, heuristics, and event processing.
