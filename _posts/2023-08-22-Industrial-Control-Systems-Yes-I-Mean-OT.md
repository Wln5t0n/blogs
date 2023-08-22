---
title: Industrial Control Systems Yes I Mean OT
tags: ICS OT Control-System Industrial-control-systems PLC SCADA Purdue-Model HMIS
---

![american-public-power-association-bv2pvCGMtzg-unsplash](https://github.com/Wln5t0n/blogs/assets/85233203/6e09257a-baa1-46e0-a55f-e5231a85fb49)

#### Lets understand Control systems and their processes!

A device, or set of devices, that manages, commands, directs, or regulates the behavior of other devices or systems.
- A device that can influence the 'real world'
- A system that bridges cyber-to-physical

Simple example: Thermostats in our homes
-  Keep temperatures at desired temperatures
- Turn on/off furnace and air conditioners
- What can an attacker do if he gains control of this?

**Industrial control systems (ICS)**
- Exponentially larger, more complex, and more dangerous

---

Control systems are defined here as "a device, or set of devices, that manages, commands, directs, or regulates the behavior of other devices or systems.'' This can take a variety of shapes, from a large chemical processing plant to the system controlling your gas furnace at home. The system takes a set of input data from its devices (such as a thermostat), performs logic on that data (the temperature is 70°F  when it should be 72°F ), and activates components to affect that sensor data (I'll turn on the fireplace so it heats back up to 72°F).

This is a gross simplification, but for example, what kind of logic is required to be energy efficient so the heat of the house isn't constantly bouncing between 72oF and 68oF as the furnace kicks on and off again? Or, what if the temperature sensor fails and reports the room to be 00F when it is really 78°F? What kind of mechanisms are in place to handle this?

What happens if the thermostat is IP-based and an attacker manages to fool the system into thinking it's 70°F when it's really 5°F?

Simply, a control system gathers information and then performs a function based on established parameters and/or information it received. ICS can vary in size and complexity based upon the process it is responsible for monitoring and controlling. ICS can be found in very specific applications (e.g., found on a small skid-mounted system) or manage something as large as a multiple-unit generation facility or oil refinery.

**Reference:**
ISA-62443.01.0I definitions, [http://std.iec.ch/glossary](http://std.iec.ch/glossary)

![ICS_INFRA-NIST](https://github.com/Wln5t0n/blogs/assets/85233203/8d1350c0-5261-4e9a-9fdf-5ea8342ae5e8)

The logic diagram shown displays typical inputs and outputs to the various control system components as well as typical operations that are performed by the various components. 

Control systems can be very difficult and costly to replace and adjust. This is one of the reasons why security in this space is lagging behind. Refreshing a control system is something done very rarely. It is not unusual for a system to remain in place for 20+ years without many changes.

**General size of points monitored or controlled:**

- Small: 1-2 Workstations, l-2 Controllers, 0-599 points
- Medium: 3-8 Workstations, 3-8 Controllers, 600-1,499 points
- Large: 8+ Workstations,8+ Controllers, 1,500+ points

### ICS PROCESS MODELS

There are four main ICS process models
- Discrete
- Batch
- Continuous
- Hybrid

These models have general definitions and are the basic precept for the type of process to be instrumented, monitored, and controlled by an ICS

#### Discrete

It is a type of process where a specified quantity of material moves as a unit between workstations, and each unit maintains its unique identity.

This process is used in many manufacturing, motion, and packaging applications. Robotic assembly, such as that found in automotive production, can be characterized as a discrete process control. Most discrete manufacturing involves the production of discrete pieces of product, such as metal stamping (license plates).

#### Batch

Some applications require that specific quantities of raw materials be combined in specific ways for particular durations to produce an intermediate or end result. One example is the production of adhesives and glues, which normally require the mixing of raw materials in a heated vessel for a period of time to form a quantity of end product. Other important examples are the production of food, beverages, and medicine. Batch processes are generally used to produce a relatively low to intermediate quantity of product per year (a few pounds to millions of pounds).

#### Continuous

A physical System is often represented through variables that are Smooth and uninterrupted in time. The control of the water temperature in a heating jacket is an example of continuous process control. Some important continuous processes are the production of fuels, chemicals, and plastics. Continuous processes in manufacturing are used to produce very large quantities of product per year (millions to billions of pounds).

#### Hybrid

A hybrid process is a combination of `discrete` and `continuous` components Tend to be hierarchical We usually defend at this level

Hybrid systems are generally understood as reactive systems that intermix discrete and continuous components. Hybrid control systems are typically found when continuous processes interact with or are supervised by sequential machines. A hybrid process model allows the controller to optimize the process based on many variables that may change the efficiency of the process at any given moment. Examples of such systems include flexible manufacturing and chemical process control systems, interconnected power systems, intelligent vehicle highway systems, and air traffic management systems.

### PURDUE ENTERPRISE REFERENCE ARCHITECTURE (PERA)

The Purdue Enterprise Reference Architecture (PERA) was one of the first reference architectures for ICS networks. It was designed by a public/private consortium made up of individuals from the and Purdue Uni This effort was led by `Theodore J. Williams`, a professor of chemical and electrical engineering programs at Purdue become very popular for designing ICS networks and has been adopted and expanded by later reference models.

The Purdue model suggests dividing your systems into five different levels, numbered zero through four lowest level, representing the physical process and the immediate sensors and actuators that make up that process. Level I represents the controllers. Level 2 is the supervisory level, where our master servers, Human Machine Interfaces (HMIs), and historians sit. Level 3 is the operations support, containing systems that support operations but that are not directly involved with the real-time execution of the process. And finally, Level 4 represents the business side of the organization related to ICS.



To understand the complexity of the OT environment, the Extended Purdue model was developed which is derived from the generic ICS model and applies specific layers defined within Table 1.

![ICS_INFRA-Table](https://github.com/Wln5t0n/blogs/assets/85233203/bf0ffd53-b35f-48da-98da-4eba4cb42ccd)

### Extended Purdue Model

![Extended-Purdue-Model](https://github.com/Wln5t0n/blogs/assets/85233203/08abb462-05df-4b47-9fcd-61ab416f38e9)


To make cybersecurity better, NIST 800-82r2 creates different zones. These zones need clear explanations. The next part will talk about these zones from NIST 800-82r2. There's also a picture that helps understand these zones better. You can find more detailed information about NIST 800-82r2 in the references section.

### Now lets understand what is Programmable Logic Controllers (PLC)

In 1968, GM sought a replacement for these costly relay systems. The winning proposal came from Bedford Associates, who founded Modicon, which stood for Modular Digital Controller, to build the first PLC. This allowed cheap and rapid programming changes to be made in minutes instead of days.

PLCs are computer-based, solid-state devices that control industrial equipment and processes. Although PLCs are control System components used throughout SCADA and DCSs. they are often the primary components in smaller control System configurations used to provide operational control of discrete processes, such as automobile assembly lines and power plant soot blower controls. PLCs are used extensively in almost all industrial processes.

**A small Allen Bradley PLC with processor and I/O cards**

<img width="472" alt="Allen-Bradley-PLC" src="https://github.com/Wln5t0n/blogs/assets/85233203/43fba2b3-15ce-4a05-812e-afb05cf902d5">

A PLC is often used to control relatively small processes, such as one leg of an assembly line or other process with a few components. From a few up to a few hundred Input/Output (I/O) points each. Supervisory Control And Data Acquisition (SCADA) refers to multiple PLCs networked together for control of multiple small processes, often including small processes at remote sites.  A Distributed Control System (DCS) is used for larger processes, such as a power generation process or other centralized plantwide control, using Distributed Processing Units (DPU) on a dedicated network with each DPU handling thousands of points of I/O.

### What is Industrial Control Systems (ICS) ?
PLC, DPU, SCADA, and DCS all fall into the category of ICS. The architecture of a PLC is theoretically similar to a DPU, so we will look at PLCs more closely as a model.

![ICS_INFRA-ICS](https://github.com/Wln5t0n/blogs/assets/85233203/7bd1b876-fa66-4c6a-89b0-1900cc07c916)


Other components that round out a complete ICS. 
- HMI – Human Machine Interface 
- ENG – Engineering workstation 
- HIST – Process data archive

![[ICS_INFRA-ICS.png]]

### HUMAN MACHINE INTERFACES (HMIS)

The Human Machine Interface is what most people think of first when considering a control system (much like your grandmother who brings her flat-screen monitor in to get a virus removed and leaves the tower at home). This is the GUI for the process, and yes, most of them look that old (it's a recurring theme you'll see through out the class).

![SCADA-HMI](https://github.com/Wln5t0n/blogs/assets/85233203/74bb55d6-761b-48c2-8739-703f9ff71a84)

The HMI is usually organized as a model diagram of the process. If you are looking at a chemical system, the screen is going to contain pump icons, tanks and levels, flow indicators, and agitator indicators to let the operator know what's happening with the process. This diagram was created by the process integrator or operator when the system was being assembled.

Additionally, an HMI is responsible for displaying important information to the operator. If a chemical tank is about to overflow. for example. the operator probably knew about that immediately (in addition to the system exacting safety logic and automatically shutting down pumps).

What the HMI may be indispensable for, however, is for manual control of the process. Manual controls may exist on individual components, but it is not uncommon for ICSs to be very large or to have components in remote locations that make actually visiting the devices problematic.

**Reference:**
[https://www.wonderware.com/](https://www.wonderware.com/)

That's it for this blog I will try to cover more topics related to ICS later. 
Hope you guys find this blog interesting.

**Activate-Windows(Wln5t0n)**

