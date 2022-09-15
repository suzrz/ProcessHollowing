# Process Hollowing

Process hollowing is a technique to hide a presence of a process. The idea 
behind is that an application creates a legitimate process in suspended state. 
Then the memory of this process is unmapped and replaced with an image that we 
want to run. Then the hollowed process is resumed.