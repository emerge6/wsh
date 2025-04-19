# WSH
Well Shell (wsh)
Welcome to wsh, a lightweight, customizable Unix shell written in C++! I built wsh to be a simple yet powerful alternative to traditional shells like Bash or Zsh, with a focus on ease of use, scripting capabilities, and a clean user experience. It’s perfect for users who want a minimal shell with modern features like tab completion, job control, and colorful prompts, without the bloat of larger shells.
Features

Interactive Prompt: Customizable prompts with predefined styles (minimal, colorful, detailed) and color support (e.g., green username, blue directory).
Built-in Commands: Essential commands like cd, echo, alias, setenv, export, jobs, fg, bg, and more.
Scripting Support: Write scripts with if, for, while, case, and custom functions. Supports command substitution ($(...)) and variable expansion.
Job Control: Run processes in the background (&), manage jobs with jobs, fg, and bg.
Tab Completion: Autocomplete commands, aliases, functions, variables, and files/directories.
Tilde Expansion: Use ~ for home directory paths (e.g., cd ~/devel).
History: Persistent command history with arrow key navigation.
Aliases: Create shortcuts for commands (e.g., alias ll='ls -l').
Variable Assignment: Set variables directly (e.g., FOO=bar) or with setenv.
Stable Program Execution: Run complex programs like neofetch and hyfetch without crashes.

Installation
Prerequisites

A Unix-like system (Linux, macOS, BSD, etc.)
g++ (C++17 or later)
libreadline-dev (for interactive input and history)
Root access for installing to /usr/bin

Build and Install

Clone the repository:git clone https://github.com/yourusername/wsh.git
cd wsh


Compile the shell:g++ -o wsh wsh.cpp -lreadline -std=c++17


Install to /usr/bin:sudo mv wsh /usr/bin/
chmod +x /usr/bin/wsh



Alternatively, edit ~/.wshrc with your preferred editor:vim ~/.wshrc



Optional: System-Wide Configuration
To make wsh available as a login shell:
sudo sh -c "echo /usr/bin/wsh >> /etc/shells"
chsh -s /usr/bin/wsh

Usage
Start wsh by running:
wsh

You’ll see a welcome message and a colorful prompt:
Welcome to Well Shell (wsh)! Enjoy your session!
Owner: mkfs (UID: 1000)
Shell: /usr/bin/wsh
Directory /home/mkfs/devel exists
System Information:
User: mkfs
Host: xfs
Shell: /usr/bin/wsh
Current Directory: /home/mkfs
Test Variable: hello
mkfs@xfs:/home/mkfs(0) $

Example Commands

Navigate Directories:cd ~/devel


Run Programs:neofetch


Set Variables:FOO=bar
echo $FOO  # Outputs: bar


Use Aliases:alias ll='ls -l'
ll  # Runs ls -l


Customize Prompt:setprompt minimal  # Simple user:dir $ prompt
setprompt colorful red cyan  # Red username, cyan directory
setprompt preview detailed  # Preview a detailed prompt


Run a Script:Create test.wsh:#!/usr/bin/wsh
echo "Time: $(date)"
sysinfo

Run it:chmod +x test.wsh
./test.wsh



Configuration
The ~/.wshrc file is where you customize wsh. Here’s a sample:
# Environment variables
setenv SHELL '/usr/bin/wsh'
TESTVAR=hello

# Prompt
setprompt colorful green blue

# Aliases
alias ls='ls --color=auto'
alias nf='neofetch'

# Functions
function check_files {
    if test -d "$1" ; then
        echo "Directory $1 exists"
    else
        echo "Directory $1 does not exist"
    fi
}

Run source ~/.wshrc to reload changes.
Troubleshooting

Programs like neofetch crash the shell:Ensure you’re using the latest version. Check terminal settings with stty -a and report issues.
Variable assignment fails:Use FOO=bar or setenv FOO bar. Verify with echo $FOO.
Prompt looks weird:Check your terminal’s ANSI color support. Try setprompt minimal for a basic prompt.
Permission issues with .wshrc:Run chmod 644 ~/.wshrc. If using doas, try:xhost +local:
doas vim ~/.wshrc



Contributing
I’d love for you to contribute to wsh! Here’s how:

Fork the repo and create a branch:git checkout -b feature/your-feature


Make changes and test thoroughly.
Submit a pull request with a clear description.

Ideas for Contributions

Add new builtins (e.g., history, set).
Enhance prompt with git branch or time.
Improve command substitution for nested commands.
Add support for arrays or traps.

License
wsh is licensed under the MIT License. See LICENSE for details.
Contact
Got questions or ideas? Open an issue on GitHub or reach out to me at your.email@example.com. Happy shelling!

Built with ☕ and a love for Unix shells.
