# nanolog
Experimental Thumb2 / ARM v7E-M elf rewriter.

Q: Can we post-process an elf to replace fat printf-style format strings with tiny packed binary metadata instead?

A: Maybe? Put the format strings in their own section, simulate instruction flow through each function and capture r0 at all nanolog call sites. De-duplicate the format strings and replace each unique format string with a packed binary blob containing a GUID, # args, and bit-packed representation of args. Then, in your log handler, just grab the tiny constant metadata blob and extracted varargs, pack them up, and send them to a host. The rewriter emits a JSON file that maps GUIDs to format strings so you can use it for codegen or dynamic string formatting in the host process.

Don't use this yet. Maybe don't use this ever. It's really just an experiment. Wouldn't it be cool, though?
