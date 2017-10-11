# ServiceTest
Memory sharing between system service and user process

There are three projects in this repo

# SendFrame
Command line application that creates memory object, then generates and writes video frames into this memory.
This application runs in the user account space, and can also be running in a different user space in multi-user PC configuration.
The shared memory is created in the Global space.

# Service
Local System account service that is allowed to intract with the desktop. This is a service version of the SendFrame program. 
Information about global memory creation, mapping it, and starting/ending generating frames are logged in the application log of EventViever. 

Use: CppWindowsService.exe -parameter
Parameters:
 -install  to install the service.
 -remove   to remove the service.

 Start and stop the service from the Services control panel. Sending of the frames will start automatically when service is started.

 # GSTesting
 This is a client application that maps the view of the Global memory space of either SendFrame, or Service running project (one at a time)
 After mapping to the memory the data in the memory are read and ingested to GStreamer pipeline that draws the video on the monitor.
 This application should run in the user account space.
