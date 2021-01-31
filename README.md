# Objective Abstraction in Malware Analysis

This repository is home to a research project focused on applying the concepts of Capability Abstraction (introduced by [SpectreOps](https://posts.specterops.io/capability-abstraction-fbeaeeb26384)) to arbitrary malware samples. The intention for this work is to devise a model of abstraction that codifies the objectives of various malware (in this context objectives are defined as emergent properties of the malwares behavior), and then to use this model to pin a range of detections beneath these objectives and procedures to create robust detection strucutres that will persist accross malware evolutions. 

In the pursuit of this goal the first phase of this research is concerned with the interplay between malware detection and evolution. To simulate this process a contrived malware sample has been developed. The first phase of this research will involve adapting the Capability Abstraction model to apply to several increasingly sophisticated iterations of the simulated malware. In the latter part of the research, the derived model will be applied to a real world sample. 

Each directory in this repo contains an iteration of the simulated malware, with the lowest version number being the least sophisticated and the higher version numbers being more sophisticated. Within the each directory is a report about the malwares functionality and the derived detections, as well as some exploration of the relation between that stage of the malwares evolution and the Capability Abstraction model. 

__Note__: the simulated malware in this repo is not designed for use in real world engagements. It is noisy, contains hardcoded URLs that are designed for use in simulated lab networks, and does not achieve it's simulated objectives. For instance, the global API hooking mechanism adds a DLL to AppInit_DLLs that hooks FindNextFileW, ostensibly to hide the presence of the executable. However, this doesn't actually hide the executable as Windows does not use the hooked function internally. Rather, this functionality was included to study the machinations of the MHook library and the general procedures involved in global API hooking. It is not advised to use this malware in any real word/test engagements. 
