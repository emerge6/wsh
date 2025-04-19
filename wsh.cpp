#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <fstream>
#include <map>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <pwd.h>
#include <regex>
#include <glob.h>
#include <dirent.h>
#include <fnmatch.h>
#include <memory>
#include <termios.h>

#define SHELL_NAME "wsh"
#define CONFIG_FILE ".wshrc"
#define HISTORY_FILE ".wsh_history"

#define COLOR_RESET "\033[0m"
#define COLOR_GREEN "\033[32m"
#define COLOR_BLUE "\033[34m"
#define COLOR_RED "\033[31m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_CYAN "\033[36m"

std::map<std::string, std::string> aliases;
std::map<std::string, std::string> variables;
std::map<std::string, std::vector<std::string>> functions;
std::string prompt_format = "\\u@\\h:\\w $ ";
std::string prompt_style = "default";
std::string prompt_user_color = COLOR_GREEN;
std::string prompt_dir_color = COLOR_BLUE;
struct Job {
    pid_t pid;
    std::string command;
    bool stopped;
};
std::vector<Job> jobs;

void wsh_loop();
std::vector<std::string> split_line(const std::string& line, bool preserve_quotes = false);
std::vector<std::string> expand_globs(const std::vector<std::string>& args);
std::string expand_tilde(const std::string& path);
bool is_builtin(const std::string& command);
int get_builtin_index(const std::string& command);
void launch_program(std::vector<std::string> args, bool background = false, int in_fd = STDIN_FILENO, int out_fd = STDOUT_FILENO);
void wsh_configure();
void load_history();
void save_history();
void handle_signal(int sig);
std::string replace_aliases(const std::string& line, int depth = 0);
std::string expand_variables(const std::string& line, const std::map<std::string, std::string>& local_vars = {});
std::string get_prompt();
void execute_script(const std::string& script_path, bool is_config = false);
void execute_line(const std::string& line, std::map<std::string, std::string>& local_vars);
void execute_function(const std::string& func_name, const std::vector<std::string>& args, std::map<std::string, std::string>& local_vars);
void setup_completer();
int evaluate_condition(const std::vector<std::string>& args);
long evaluate_arithmetic(const std::string& expr);
std::string execute_command_substitution(const std::string& command);

int wsh_cd(std::vector<std::string> args);
int wsh_exit(std::vector<std::string> args);
int wsh_help(std::vector<std::string> args);
int wsh_alias(std::vector<std::string> args);
int wsh_setenv(std::vector<std::string> args);
int wsh_setprompt(std::vector<std::string> args);
int wsh_source(std::vector<std::string> args);
int wsh_owner(std::vector<std::string> args);
int wsh_export(std::vector<std::string> args);
int wsh_unset(std::vector<std::string> args);
int wsh_echo(std::vector<std::string> args);
int wsh_test(std::vector<std::string> args);
int wsh_jobs(std::vector<std::string> args);
int wsh_fg(std::vector<std::string> args);
int wsh_bg(std::vector<std::string> args);

std::vector<std::string> builtin_commands = {"cd", "exit", "help", "alias", "setenv", "setprompt", "source", "owner", "export", "unset", "echo", "test", "jobs", "fg", "bg"};
using builtin_func = int (*)(std::vector<std::string>);
std::vector<builtin_func> builtin_functions = {wsh_cd, wsh_exit, wsh_help, wsh_alias, wsh_setenv, wsh_setprompt, wsh_source, wsh_owner, wsh_export, wsh_unset, wsh_echo, wsh_test, wsh_jobs, wsh_fg, wsh_bg};

void wsh_loop() {
    load_history();
    setup_completer();
    std::string line;
    std::map<std::string, std::string> local_vars;

    while (true) {
        std::string prompt = get_prompt();
        char* input = readline(prompt.c_str());
        if (!input) break; // crtl d
        line = std::string(input);
        free(input);

        if (line.empty()) continue;
        add_history(line.c_str());
        save_history();

        execute_line(line, local_vars);
    }
}

std::vector<std::string> split_line(const std::string& line, bool preserve_quotes) {
    std::vector<std::string> tokens;
    std::string token;
    bool in_quotes = false;
    char quote_char = 0;
    bool escaped = false;

    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (escaped) {
            token += c;
            escaped = false;
            continue;
        }
        if (c == '\\') {
            escaped = true;
            continue;
        }
        if (c == '"' || c == '\'') {
            if (in_quotes && c == quote_char) {
                in_quotes = false;
                if (preserve_quotes) token += c;
            } else if (!in_quotes) {
                in_quotes = true;
                quote_char = c;
                if (preserve_quotes) token += c;
            } else {
                token += c;
            }
        } else if (std::isspace(c) && !in_quotes) {
            if (!token.empty()) {
                if (!preserve_quotes && token.size() > 1 && (token.front() == '\'' || token.front() == '"') && token.front() == token.back()) {
                    token = token.substr(1, token.size() - 2);
                }
                tokens.push_back(token);
                token.clear();
            }
        } else {
            token += c;
        }
    }
    if (!token.empty()) {
        if (!preserve_quotes && token.size() > 1 && (token.front() == '\'' || token.front() == '"') && token.front() == token.back()) {
            token = token.substr(1, token.size() - 2);
        }
        tokens.push_back(token);
    }
    if (in_quotes) {
        std::cerr << COLOR_RED << "wsh: unclosed quote" << COLOR_RESET << std::endl;
    }
    return tokens;
}

std::vector<std::string> expand_globs(const std::vector<std::string>& args) {
    std::vector<std::string> expanded;
    for (auto arg : args) {
        arg = expand_tilde(arg);
        if (arg.find('*') != std::string::npos || arg.find('?') != std::string::npos) {
            glob_t glob_result;
            if (glob(arg.c_str(), GLOB_TILDE | GLOB_NOCHECK, nullptr, &glob_result) == 0) {
                for (size_t i = 0; i < glob_result.gl_pathc; ++i) {
                    expanded.push_back(glob_result.gl_pathv[i]);
                }
                globfree(&glob_result);
            } else {
                expanded.push_back(arg);
            }
        } else {
            expanded.push_back(arg);
        }
    }
    return expanded;
}

std::string expand_tilde(const std::string& path) {
    if (path.empty() || path[0] != '~') return path;
    std::string home = getenv("HOME") ? getenv("HOME") : "/home/user";
    if (path == "~") return home;
    if (path[1] == '/' || path[1] == '\0') return home + path.substr(1);
    return path;
}

bool is_builtin(const std::string& command) {
    return std::find(builtin_commands.begin(), builtin_commands.end(), command) != builtin_commands.end();
}

int get_builtin_index(const std::string& command) {
    auto it = std::find(builtin_commands.begin(), builtin_commands.end(), command);
    return (it != builtin_commands.end()) ? std::distance(builtin_commands.begin(), it) : -1;
}

std::string replace_aliases(const std::string& line, int depth) {
    if (depth > 10) {
        return line;
    }
    std::vector<std::string> tokens = split_line(line, true);
    if (tokens.empty()) return line;

    auto it = aliases.find(tokens[0]);
    if (it != aliases.end()) {
        std::string new_line = it->second;
        for (size_t i = 1; i < tokens.size(); ++i) {
            new_line += " " + tokens[i];
        }
        return replace_aliases(new_line, depth + 1);
    }
    return line;
}

std::string execute_command_substitution(const std::string& command) {
    std::vector<std::string> args = split_line(command, false);
    if (args.empty()) return "";

    int pipefd[2];
    if (pipe(pipefd) == -1) {
        std::cerr << COLOR_RED << "wsh: pipe failed: " << strerror(errno) << COLOR_RESET << std::endl;
        return "";
    }

    pid_t pid = fork();
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);

        std::vector<char*> c_args;
        for (auto& arg : args) {
            c_args.push_back(const_cast<char*>(arg.c_str()));
        }
        c_args.push_back(nullptr);
        execvp(c_args[0], c_args.data());
        std::cerr << COLOR_RED << "wsh: command not found: " << args[0] << COLOR_RESET << std::endl;
        exit(127);
    } else if (pid > 0) {
        close(pipefd[1]);
        char buffer[4096];
        std::string output;
        ssize_t n;
        while ((n = read(pipefd[0], buffer, sizeof(buffer) - 1)) > 0) {
            buffer[n] = '\0';
            output += buffer;
        }
        close(pipefd[0]);
        int status;
        waitpid(pid, &status, 0);
        output.erase(std::remove(output.begin(), output.end(), '\n'), output.end());
        return output;
    } else {
        std::cerr << COLOR_RED << "wsh: fork failed: " << strerror(errno) << COLOR_RESET << std::endl;
        close(pipefd[0]);
        close(pipefd[1]);
        return "";
    }
}

std::string expand_variables(const std::string& line, const std::map<std::string, std::string>& local_vars) {
    std::string expanded = line;
    std::regex var_regex("\\$\\{([a-zA-Z_][a-zA-Z0-9_]*)(:[-=][^}]*)?\\}|\\$([a-zA-Z_][a-zA-Z0-9_]*)|\\$\\$|\\$\\(([^)]+)\\)");
    std::smatch match;

    while (std::regex_search(expanded, match, var_regex)) {
        std::string replacement;
        if (match[0] == "$$") {
            replacement = std::to_string(getpid());
        } else if (match[1].length() > 0) {
            std::string var_name = match[1].str();
            std::string modifier = match[2].length() > 2 ? match[2].str().substr(1) : "";
            auto local_it = local_vars.find(var_name);
            if (local_it != local_vars.end()) {
                replacement = local_it->second;
            } else {
                auto global_it = variables.find(var_name);
                if (global_it != variables.end()) {
                    replacement = global_it->second;
                } else if (char* env = getenv(var_name.c_str())) {
                    replacement = env;
                } else if (!modifier.empty()) {
                    if (modifier[0] == '-') {
                        replacement = modifier.substr(1);
                    } else if (modifier[0] == '=') {
                        replacement = modifier.substr(1);
                        variables[var_name] = replacement;
                        setenv(var_name.c_str(), replacement.c_str(), 1);
                    }
                }
            }
        } else if (match[3].length() > 0) {
            std::string var_name = match[3].str();
            auto local_it = local_vars.find(var_name);
            if (local_it != local_vars.end()) {
                replacement = local_it->second;
            } else {
                auto global_it = variables.find(var_name);
                if (global_it != variables.end()) {
                    replacement = global_it->second;
                } else if (char* env = getenv(var_name.c_str())) {
                    replacement = env;
                }
            }
        } else if (match[4].length() > 0) {
            std::string cmd = match[4].str();
            replacement = execute_command_substitution(cmd);
        }
        expanded.replace(match.position(), match.length(), replacement);
    }
    return expanded;
}

std::string get_prompt() {
    std::string prompt;
    if (prompt_style == "minimal") {
        prompt = prompt_user_color + "\\u" + COLOR_RESET + ":" + prompt_dir_color + "\\w" + COLOR_RESET + "$ ";
    } else if (prompt_style == "colorful") {
        prompt = prompt_user_color + "\\u@\\h" + COLOR_RESET + ":" + prompt_dir_color + "\\w" + COLOR_RESET + "(\\j) $ ";
    } else if (prompt_style == "detailed") {
        prompt = prompt_user_color + "\\u@\\h" + COLOR_RESET + "[" + prompt_dir_color + "\\w" + COLOR_RESET + "] #\\! $ ";
    } else {
        prompt = expand_variables(prompt_format);
    }

    std::string username = getenv("USER") ? getenv("USER") : "user";
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == -1) {
        strcpy(hostname, "localhost");
    }
    char* cwd = getcwd(nullptr, 0);
    std::string cwd_str = cwd ? cwd : ".";
    std::string shlvl = getenv("SHLVL") ? getenv("SHLVL") : "1";
    std::string jobs_count = std::to_string(jobs.size());
    static int command_number = 0;
    std::string cmd_num = std::to_string(++command_number);

    prompt = std::regex_replace(prompt, std::regex("\\\\u"), username);
    prompt = std::regex_replace(prompt, std::regex("\\\\h"), hostname);
    prompt = std::regex_replace(prompt, std::regex("\\\\w"), cwd_str);
    prompt = std::regex_replace(prompt, std::regex("\\\\s"), SHELL_NAME);
    prompt = std::regex_replace(prompt, std::regex("\\\\#"), shlvl);
    prompt = std::regex_replace(prompt, std::regex("\\\\j"), jobs_count);
    prompt = std::regex_replace(prompt, std::regex("\\\\!"), cmd_num);
    free(cwd);
    return prompt;
}

void launch_program(std::vector<std::string> args, bool background, int in_fd, int out_fd) {
    struct termios old_tio, new_tio;
    tcgetattr(STDIN_FILENO, &old_tio);
    new_tio = old_tio;
    new_tio.c_lflag |= (ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &new_tio);

    pid_t pid = fork();
    if (pid == 0) {
        if (in_fd != STDIN_FILENO) {
            dup2(in_fd, STDIN_FILENO);
            close(in_fd);
        }
        if (out_fd != STDOUT_FILENO) {
            dup2(out_fd, STDOUT_FILENO);
            close(out_fd);
        }
        signal(SIGTSTP, SIG_DFL);
        signal(SIGINT, SIG_DFL);
        signal(SIGCHLD, SIG_DFL);

        std::vector<char*> c_args;
        for (auto& arg : args) {
            c_args.push_back(const_cast<char*>(arg.c_str()));
        }
        c_args.push_back(nullptr);
        execvp(c_args[0], c_args.data());
        std::cerr << COLOR_RED << "wsh: command not found: " << args[0] << COLOR_RESET << std::endl;
        tcsetattr(STDIN_FILENO, TCSANOW, &old_tio);
        exit(127);
    } else if (pid > 0) {
        tcsetattr(STDIN_FILENO, TCSANOW, &old_tio);
        if (!background) {
            int status;
            waitpid(pid, &status, WUNTRACED);
            if (WIFSTOPPED(status)) {
                jobs.push_back({pid, args[0], true});
                std::cout << "[" << jobs.size() << "] Stopped " << args[0] << "\n";
            }
        } else {
            jobs.push_back({pid, args[0], false});
            std::cout << "[" << jobs.size() << "] " << pid << " " << args[0] << "\n";
        }
    } else {
        std::cerr << COLOR_RED << "wsh: fork failed: " << strerror(errno) << COLOR_RESET << std::endl;
        tcsetattr(STDIN_FILENO, TCSANOW, &old_tio);
    }
}

void execute_command(std::vector<std::string> args, std::map<std::string, std::string>& local_vars, bool background) {
    if (args.empty()) return;

    args = expand_globs(args);
    std::vector<std::vector<std::string>> pipeline;
    std::vector<std::string> current_cmd;
    int out_fd = STDOUT_FILENO;
    int in_fd = STDIN_FILENO;
    bool append = false;

    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "|") {
            pipeline.push_back(current_cmd);
            current_cmd.clear();
        } else if (args[i] == ">" || args[i] == ">>") {
            if (i + 1 < args.size()) {
                append = (args[i] == ">>");
                std::string file = expand_tilde(args[++i]);
                out_fd = open(file.c_str(), O_WRONLY | O_CREAT | (append ? O_APPEND : O_TRUNC), 0644);
                if (out_fd < 0) {
                    std::cerr << COLOR_RED << "wsh: cannot open file: " << args[i] << ": " << strerror(errno) << COLOR_RESET << std::endl;
                    return;
                }
            }
        } else if (args[i] == "<") {
            if (i + 1 < args.size()) {
                std::string file = expand_tilde(args[++i]);
                in_fd = open(file.c_str(), O_RDONLY);
                if (in_fd < 0) {
                    std::cerr << COLOR_RED << "wsh: cannot open file: " << args[i] << ": " << strerror(errno) << COLOR_RESET << std::endl;
                    return;
                }
            }
        } else {
            current_cmd.push_back(args[i]);
        }
    }
    if (!current_cmd.empty()) pipeline.push_back(current_cmd);

    int pipefd[2];
    int prev_fd = in_fd;
    for (size_t i = 0; i < pipeline.size(); ++i) {
        bool is_last = (i == pipeline.size() - 1);
        if (!is_last) {
            if (pipe(pipefd) == -1) {
                std::cerr << COLOR_RED << "wsh: pipe failed: " << strerror(errno) << COLOR_RESET << std::endl;
                return;
            }
            out_fd = pipefd[1];
        } else {
            out_fd = (out_fd == STDOUT_FILENO) ? STDOUT_FILENO : out_fd;
        }

        if (is_builtin(pipeline[i][0])) {
            int index = get_builtin_index(pipeline[i][0]);
            if (out_fd != STDOUT_FILENO) {
                dup2(out_fd, STDOUT_FILENO);
                close(out_fd);
            }
            if (prev_fd != STDIN_FILENO) {
                dup2(prev_fd, STDIN_FILENO);
                close(prev_fd);
            }
            builtin_functions[index](pipeline[i]);
        } else if (functions.find(pipeline[i][0]) != functions.end()) {
            if (out_fd != STDOUT_FILENO) {
                dup2(out_fd, STDOUT_FILENO);
                close(out_fd);
            }
            if (prev_fd != STDIN_FILENO) {
                dup2(prev_fd, STDIN_FILENO);
                close(prev_fd);
            }
            execute_function(pipeline[i][0], std::vector<std::string>(pipeline[i].begin() + 1, pipeline[i].end()), local_vars);
        } else {
            launch_program(pipeline[i], background && is_last, prev_fd, out_fd);
        }

        if (!is_last) {
            close(out_fd);
            prev_fd = pipefd[0];
        }
    }
    if (in_fd != STDIN_FILENO) close(in_fd);
    if (out_fd != STDOUT_FILENO && out_fd != pipefd[1]) close(out_fd);
}

long evaluate_arithmetic(const std::string& expr) {
    std::string clean_expr = expr;
    clean_expr.erase(std::remove_if(clean_expr.begin(), clean_expr.end(), ::isspace), clean_expr.end());
    if (clean_expr.empty()) return 0;

    try {
        std::string::size_type pos = 0;
        long result = 0;
        if (clean_expr.find('+') != std::string::npos) {
            auto parts = split_line(clean_expr, false);
            if (parts.size() == 3 && parts[1] == "+") {
                result = std::stol(parts[0]) + std::stol(parts[2]);
            }
        } else if (clean_expr.find('-') != std::string::npos) {
            auto parts = split_line(clean_expr, false);
            if (parts.size() == 3 && parts[1] == "-") {
                result = std::stol(parts[0]) - std::stol(parts[2]);
            }
        } else {
            result = std::stol(clean_expr, &pos);
            if (pos != clean_expr.size()) throw std::invalid_argument("invalid expression");
        }
        return result;
    } catch (...) {
        std::cerr << COLOR_RED << "wsh: invalid arithmetic expression: " << expr << COLOR_RESET << std::endl;
        return 0;
    }
}

int evaluate_condition(const std::vector<std::string>& args) {
    if (args.size() < 2) return 1;
    if (args[1] == "-f") {
        return args.size() > 2 && access(expand_tilde(args[2]).c_str(), F_OK) == 0 ? 0 : 1;
    } else if (args[1] == "-d") {
        struct stat st;
        return args.size() > 2 && ::stat(expand_tilde(args[2]).c_str(), &st) == 0 && S_ISDIR(st.st_mode) ? 0 : 1;
    } else if (args[1] == "=") {
        return args.size() > 3 && args[2] == args[3] ? 0 : 1;
    } else if (args[1] == "-eq") {
        try {
            return args.size() > 3 && std::stol(args[2]) == std::stol(args[3]) ? 0 : 1;
        } catch (...) {
            return 1;
        }
    } else if (args[1] == "-ne") {
        try {
            return args.size() > 3 && std::stol(args[2]) != std::stol(args[3]) ? 0 : 1;
        } catch (...) {
            return 1;
        }
    } else if (args[1] == "-lt") {
        try {
            return args.size() > 3 && std::stol(args[2]) < std::stol(args[3]) ? 0 : 1;
        } catch (...) {
            return 1;
        }
    }
    std::cerr << COLOR_RED << "wsh: unknown test operator: " << args[1] << COLOR_RESET << std::endl;
    return 1;
}

void execute_function(const std::string& func_name, const std::vector<std::string>& args, std::map<std::string, std::string>& local_vars) {
    auto it = functions.find(func_name);
    if (it == functions.end()) return;

    std::map<std::string, std::string> func_vars = local_vars;
    for (size_t i = 0; i < args.size(); ++i) {
        func_vars[std::to_string(i + 1)] = args[i];
    }

    std::string script;
    for (const auto& line : it->second) {
        script += line + "\n";
    }
    std::istringstream script_stream(script);
    std::string line;
    while (std::getline(script_stream, line)) {
        line.erase(0, line.find_first_not_of(" \t\n\r"));
        line.erase(line.find_last_not_of(" \t\n\r") + 1);
        if (line.empty()) continue;
        execute_line(line, func_vars);
    }
}

void execute_line(const std::string& line, std::map<std::string, std::string>& local_vars) {
    std::string trimmed_line = line;
    trimmed_line.erase(0, trimmed_line.find_first_not_of(" \t\n\r"));
    trimmed_line.erase(trimmed_line.find_last_not_of(" \t\n\r") + 1);
    if (trimmed_line.empty()) return;

    std::string expanded_line = replace_aliases(trimmed_line);
    expanded_line = expand_variables(expanded_line, local_vars);
    std::vector<std::string> args = split_line(expanded_line, false);

    bool background = (!args.empty() && args.back() == "&");
    if (background) args.pop_back();

    if (args.empty()) return;

    if (args[0].find('=') != std::string::npos && !is_builtin(args[0]) && functions.find(args[0]) == functions.end()) {
        size_t eq_pos = args[0].find('=');
        std::string name = args[0].substr(0, eq_pos);
        std::string value = args[0].substr(eq_pos + 1);
        if (!name.empty() && name[0] != '$') {
            variables[name] = value;
            setenv(name.c_str(), value.c_str(), 1);
            return;
        }
    }

    if (args[0] == "if") {
        if (args.size() > 2 && args[1] == "test") {
            size_t i = 2;
            while (i < args.size() && args[i] != ";") ++i;
            if (!evaluate_condition(std::vector<std::string>(args.begin() + 1, args.begin() + i))) {
                std::string cmd;
                for (size_t j = i + 1; j < args.size(); ++j) cmd += args[j] + " ";
                execute_line(cmd, local_vars);
            }
        }
    } else if (args[0] == "then" || args[0] == "else" || args[0] == "fi" || args[0] == "}") {
    } else if (args[0] == "for") {
        if (args.size() > 4 && args[2] == "in") {
            std::string var = args[1];
            std::vector<std::string> values;
            size_t i = 3;
            while (i < args.size() && args[i] != ";") {
                values.push_back(args[i++]);
            }
            std::string cmd;
            for (size_t j = i + 1; j < args.size(); ++j) cmd += args[j] + " ";
            for (const auto& val : values) {
                local_vars[var] = val;
                execute_line(cmd, local_vars);
            }
            local_vars.erase(var);
        }
    } else if (args[0] == "while") {
        if (args.size() > 2 && args[1] == "test") {
            size_t i = 2;
            while (i < args.size() && args[i] != ";") ++i;
            std::string cmd;
            for (size_t j = i + 1; j < args.size(); ++j) cmd += args[j] + " ";
            while (!evaluate_condition(std::vector<std::string>(args.begin() + 1, args.begin() + i))) {
                execute_line(cmd, local_vars);
            }
        }
    } else if (args[0] == "((") {
        if (args.back() == "))") {
            std::string expr;
            for (size_t i = 1; i < args.size() - 1; ++i) expr += args[i];
            variables["?"] = evaluate_arithmetic(expr) ? "0" : "1";
        }
    } else if (args[0] == "case") {
        if (args.size() > 3 && args[2] == "in") {
            std::string value = args[1];
            size_t i = 3;
            while (i < args.size() && args[i] != "esac") {
                std::string pattern = args[i++];
                if (i < args.size() && args[i] == ")") {
                    ++i;
                    std::string cmd;
                    while (i < args.size() && args[i] != ";;") {
                        cmd += args[i++] + " ";
                    }
                    if (fnmatch(pattern.c_str(), value.c_str(), 0) == 0) {
                        execute_line(cmd, local_vars);
                        break;
                    }
                    if (i < args.size()) ++i;
                }
            }
        }
    } else {
        execute_command(args, local_vars, background);
    }
}

int wsh_cd(std::vector<std::string> args) {
    std::string dir = (args.size() < 2) ? getenv("HOME") : expand_tilde(args[1]);
    if (chdir(dir.c_str()) != 0) {
        std::cerr << COLOR_RED << "wsh: cd: " << dir << ": " << strerror(errno) << COLOR_RESET << std::endl;
    }
    return 1;
}

int wsh_exit(std::vector<std::string> args) {
    save_history();
    exit(0);
    return 0;
}

int wsh_help(std::vector<std::string> args) {
    std::cout << COLOR_GREEN << "Well Shell (wsh)" << COLOR_RESET << "\n";
    std::cout << "Built-in commands:\n";
    for (const auto& cmd : builtin_commands) {
        std::cout << "  " << COLOR_BLUE << cmd << COLOR_RESET << "\n";
    }
    std::cout << "Scripting: if, for, while, case, function\n";
    std::cout << "Job control: jobs, fg, bg\n";
    std::cout << "Prompt styles: setprompt {minimal|colorful|detailed|custom} [user_color dir_color]\n";
    return 1;
}

int wsh_alias(std::vector<std::string> args) {
    if (args.size() == 1) {
        for (const auto& pair : aliases) {
            std::cout << COLOR_BLUE << "alias " << pair.first << "='" << pair.second << "'" << COLOR_RESET << "\n";
        }
        return 1;
    }
    if (args.size() == 2 && args[1].find('=') == std::string::npos) {
        auto it = aliases.find(args[1]);
        if (it != aliases.end()) {
            std::cout << COLOR_BLUE << "alias " << it->first << "='" << it->second << "'" << COLOR_RESET << "\n";
        } else {
            std::cerr << COLOR_RED << "wsh: alias: " << args[1] << ": not found" << COLOR_RESET << std::endl;
        }
        return 1;
    }
    if (args.size() < 2) {
        std::cerr << COLOR_RED << "wsh: alias: usage: alias name='command'" << COLOR_RESET << std::endl;
        return 1;
    }

    std::string name, value;
    if (args[1].find('=') != std::string::npos) {
        size_t eq_pos = args[1].find('=');
        name = args[1].substr(0, eq_pos);
        value = args[1].substr(eq_pos + 1);
        if (value.size() > 1 && value.front() == '\'' && value.back() == '\'') {
            value = value.substr(1, value.size() - 2);
        }
    } else if (args.size() >= 3 && args[2].find('=') != std::string::npos) {
        size_t eq_pos = args[2].find('=');
        name = args[2].substr(0, eq_pos);
        value = args[2].substr(eq_pos + 1);
        if (value.size() > 1 && value.front() == '\'' && value.back() == '\'') {
            value = value.substr(1, value.size() - 2);
        }
    } else {
        std::cerr << COLOR_RED << "wsh: alias: usage: alias name='command'" << COLOR_RESET << std::endl;
        return 1;
    }

    aliases[name] = value;
    return 1;
}

int wsh_setenv(std::vector<std::string> args) {
    if (args.size() < 2) {
        for (const auto& pair : variables) {
            std::cout << COLOR_BLUE << pair.first << "=" << pair.second << COLOR_RESET << "\n";
        }
    } else {
        std::string value = (args.size() > 2) ? args[2] : "";
        variables[args[1]] = value;
        setenv(args[1].c_str(), value.c_str(), 1);
    }
    return 1;
}

int wsh_setprompt(std::vector<std::string> args) {
    std::map<std::string, std::string> color_map = {
        {"red", COLOR_RED},
        {"green", COLOR_GREEN},
        {"blue", COLOR_BLUE},
        {"yellow", COLOR_YELLOW},
        {"cyan", COLOR_CYAN},
        {"reset", COLOR_RESET}
    };

    if (args.size() < 2) {
        std::cout << "Current prompt style: " << prompt_style << "\n";
        std::cout << "Format: " << prompt_format << "\n";
        std::cout << "User color: " << prompt_user_color << "sample" << COLOR_RESET << "\n";
        std::cout << "Dir color: " << prompt_dir_color << "sample" << COLOR_RESET << "\n";
        return 1;
    }

    std::string style = args[1];
    if (style == "preview") {
        if (args.size() < 3) {
            std::cerr << COLOR_RED << "wsh: setprompt: usage: setprompt preview {minimal|colorful|detailed|custom format}" << COLOR_RESET << std::endl;
            return 1;
        }
        std::string temp_style = args[2];
        std::string temp_format = prompt_format;
        std::string temp_user_color = prompt_user_color;
        std::string temp_dir_color = prompt_dir_color;
        if (temp_style == "custom" && args.size() > 3) {
            temp_format = args[3];
            for (size_t i = 4; i < args.size(); ++i) temp_format += " " + args[i];
        }
        prompt_style = temp_style;
        prompt_format = temp_format;
        if (args.size() > 3 && args[2] != "custom") {
            prompt_user_color = color_map.count(args[2]) ? color_map[args[2]] : COLOR_GREEN;
            prompt_dir_color = args.size() > 3 && color_map.count(args[3]) ? color_map[args[3]] : COLOR_BLUE;
        }
        std::cout << "Preview: " << get_prompt() << "\n";
        prompt_style = style;
        prompt_format = temp_format;
        prompt_user_color = temp_user_color;
        prompt_dir_color = temp_dir_color;
        return 1;
    }

    if (style == "minimal" || style == "colorful" || style == "detailed") {
        prompt_style = style;
        if (args.size() > 2) {
            prompt_user_color = color_map.count(args[2]) ? color_map[args[2]] : COLOR_GREEN;
            prompt_dir_color = args.size() > 3 && color_map.count(args[3]) ? color_map[args[3]] : COLOR_BLUE;
        }
    } else if (style == "custom") {
        if (args.size() < 3) {
            std::cerr << COLOR_RED << "wsh: setprompt: usage: setprompt custom format" << COLOR_RESET << std::endl;
            return 1;
        }
        prompt_style = "custom";
        prompt_format = args[2];
        for (size_t i = 3; i < args.size(); ++i) {
            prompt_format += " " + args[i];
        }
    } else {
        std::cerr << COLOR_RED << "wsh: setprompt: unknown style: " << style << COLOR_RESET << std::endl;
        std::cerr << "Available styles: minimal, colorful, detailed, custom" << std::endl;
        return 1;
    }
    return 1;
}

int wsh_source(std::vector<std::string> args) {
    if (args.size() < 2) {
        std::cerr << COLOR_RED << "wsh: source: usage: source script.wsh" << COLOR_RESET << std::endl;
    } else {
        execute_script(expand_tilde(args[1]));
    }
    return 1;
}

int wsh_owner(std::vector<std::string> args) {
    struct passwd* pw = getpwuid(getuid());
    std::cout << COLOR_YELLOW << "Owner: " << (pw ? pw->pw_name : "unknown") << " (UID: " << getuid() << ")" << COLOR_RESET << "\n";
    return 1;
}

int wsh_export(std::vector<std::string> args) {
    if (args.size() < 2) {
        for (const auto& pair : variables) {
            std::cout << "export " << pair.first << "=\"" << pair.second << "\"\n";
        }
    } else {
        variables[args[1]] = (args.size() > 2) ? args[2] : "";
        setenv(args[1].c_str(), variables[args[1]].c_str(), 1);
    }
    return 1;
}

int wsh_unset(std::vector<std::string> args) {
    if (args.size() < 2) {
        std::cerr << COLOR_RED << "wsh: unset: usage: unset variable" << COLOR_RESET << std::endl;
    } else {
        variables.erase(args[1]);
        unsetenv(args[1].c_str());
    }
    return 1;
}

int wsh_echo(std::vector<std::string> args) {
    bool newline = true;
    size_t start = 1;
    if (args.size() > 1 && args[1] == "-n") {
        newline = false;
        start = 2;
    }
    for (size_t i = start; i < args.size(); ++i) {
        std::cout << args[i];
        if (i < args.size() - 1) std::cout << " ";
    }
    if (newline) std::cout << "\n";
    std::cout.flush();
    return 1;
}

int wsh_test(std::vector<std::string> args) {
    return evaluate_condition(args);
}

int wsh_jobs(std::vector<std::string> args) {
    for (size_t i = 0; i < jobs.size(); ++i) {
        std::cout << "[" << i + 1 << "] " << jobs[i].pid << " " << (jobs[i].stopped ? "Stopped" : "Running") << " " << jobs[i].command << "\n";
    }
    return 1;
}

int wsh_fg(std::vector<std::string> args) {
    if (args.size() < 2) {
        std::cerr << COLOR_RED << "wsh: fg: usage: fg %jobid" << COLOR_RESET << std::endl;
        return 1;
    }
    size_t jobid;
    try {
        jobid = std::stoul(args[1].substr(1)) - 1;
    } catch (...) {
        std::cerr << COLOR_RED << "wsh: fg: invalid jobid: " << args[1] << COLOR_RESET << std::endl;
        return 1;
    }
    if (jobid < jobs.size()) {
        pid_t pid = jobs[jobid].pid;
        kill(pid, SIGCONT);
        jobs[jobid].stopped = false;
        int status;
        waitpid(pid, &status, WUNTRACED);
        if (!WIFSTOPPED(status)) jobs.erase(jobs.begin() + jobid);
    } else {
        std::cerr << COLOR_RED << "wsh: fg: no such job: " << args[1] << COLOR_RESET << std::endl;
    }
    return 1;
}

int wsh_bg(std::vector<std::string> args) {
    if (args.size() < 2) {
        std::cerr << COLOR_RED << "wsh: bg: usage: bg %jobid" << COLOR_RESET << std::endl;
        return 1;
    }
    size_t jobid;
    try {
        jobid = std::stoul(args[1].substr(1)) - 1;
    } catch (...) {
        std::cerr << COLOR_RED << "wsh: bg: invalid jobid: " << args[1] << COLOR_RESET << std::endl;
        return 1;
    }
    if (jobid < jobs.size()) {
        pid_t pid = jobs[jobid].pid;
        kill(pid, SIGCONT);
        jobs[jobid].stopped = false;
    } else {
        std::cerr << COLOR_RED << "wsh: bg: no such job: " << args[1] << COLOR_RESET << std::endl;
    }
    return 1;
}

void wsh_configure() {
    std::string home = getenv("HOME") ? getenv("HOME") : "/home/user";
    std::string config_path = home + "/" + CONFIG_FILE;
    if (access(config_path.c_str(), F_OK) == -1) {
        std::ofstream config_file(config_path);
        config_file << "# wsh configuration file\n";
        config_file << "setenv WELCOME 'Welcome to Well Shell (wsh)! Enjoy your session!'\n";
        config_file << "setprompt colorful green blue\n";
        config_file << "setenv EDITOR 'vim'\n";
        config_file << "setenv PAGER 'less'\n";
        config_file << "setenv SHELL '/usr/bin/wsh'\n";
        config_file << "setenv HOHOL 'pidor'\n";
        config_file << "TESTVAR=hello\n";
        config_file << "alias ls='ls --color=auto'\n";
        config_file << "alias ll='ls -l'\n";
        config_file << "alias la='ls -la'\n";
        config_file << "alias l='ls -lah'\n";
        config_file << "alias grep='grep --color=auto'\n";
        config_file << "alias cls='clear'\n";
        config_file << "alias rm='rm -i'\n";
        config_file << "alias cp='cp -i'\n";
        config_file << "alias mv='mv -i'\n";
        config_file << "export PATH '${PATH:-/bin:/usr/bin}:/usr/local/bin:/home/mkfs/bin'\n";
        config_file << "function check_files {\n";
        config_file << "    if test -d \"$1\" ; then\n";
        config_file << "        echo \"Directory $1 exists\"\n";
        config_file << "    else\n";
        config_file << "        echo \"Directory $1 does not exist\"\n";
        config_file << "    fi\n";
        config_file << "}\n";
        config_file << "function sysinfo {\n";
        config_file << "    echo \"System Information:\"\n";
        config_file << "    echo \"User: $USER\"\n";
        config_file << "    echo \"Host: $HOSTNAME\"\n";
        config_file << "    echo \"Shell: $SHELL\"\n";
        config_file << "    echo \"Current Directory: $PWD\"\n";
        config_file << "    echo \"Test Variable: $TESTVAR\"\n";
        config_file << "}\n";
        config_file.close();
    }
    execute_script(config_path, true);
}

void load_history() {
    std::string home = getenv("HOME") ? getenv("HOME") : "/home/user";
    std::string history_path = home + "/" + HISTORY_FILE;
    using_history();
    read_history(history_path.c_str());
}

void save_history() {
    std::string home = getenv("HOME") ? getenv("HOME") : "/home/user";
    std::string history_path = home + "/" + HISTORY_FILE;
    write_history(history_path.c_str());
}

void handle_signal(int sig) {
    if (sig == SIGINT) {
        std::cout << "\n" << get_prompt();
        std::cout.flush();
        rl_on_new_line();
        rl_replace_line("", 0);
        rl_redisplay();
    } else if (sig == SIGCHLD) {
        pid_t pid;
        int status;
        while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
            for (auto it = jobs.begin(); it != jobs.end(); ++it) {
                if (it->pid == pid) {
                    jobs.erase(it);
                    break;
                }
            }
        }
    }
}

void execute_script(const std::string& script_path, bool is_config) {
    std::ifstream script_file(script_path);
    if (!script_file.is_open()) {
        std::cerr << COLOR_RED << "wsh: cannot open script: " << script_path << ": " << strerror(errno) << COLOR_RESET << std::endl;
        return;
    }
    std::map<std::string, std::string> local_vars;
    std::string line;
    bool skip_shebang = false;
    bool in_function = false;
    std::string func_name;
    std::vector<std::string> func_body;

    while (std::getline(script_file, line)) {
        line.erase(0, line.find_first_not_of(" \t\n\r"));
        line.erase(line.find_last_not_of(" \t\n\r") + 1);
        if (line.empty() || line[0] == '#') continue;
        if (!skip_shebang && line.find("#!/usr/bin/wsh") == 0) {
            skip_shebang = true;
            continue;
        }

        if (in_function) {
            func_body.push_back(line);
            if (line == "}") {
                in_function = false;
                functions[func_name] = func_body;
                func_body.clear();
            }
            continue;
        }

        std::vector<std::string> tokens = split_line(line, false);
        if (tokens.size() >= 3 && tokens[0] == "function" && tokens[2] == "{") {
            in_function = true;
            func_name = tokens[1];
            func_body.clear();
            continue;
        }

        execute_line(line, local_vars);
    }
    script_file.close();
}

char* command_generator(const char* text, int state) {
    static std::vector<std::string> matches;
    static size_t match_index;

    if (!state) {
        matches.clear();
        match_index = 0;
        std::string text_str = expand_tilde(text);

        for (const auto& cmd : builtin_commands) {
            if (cmd.find(text_str) == 0) matches.push_back(cmd);
        }

        for (const auto& pair : aliases) {
            if (pair.first.find(text_str) == 0) matches.push_back(pair.first);
        }

        for (const auto& pair : functions) {
            if (pair.first.find(text_str) == 0) matches.push_back(pair.first);
        }

        for (const auto& pair : variables) {
            std::string var = "$" + pair.first;
            if (var.find(text_str) == 0) matches.push_back(var);
        }

        char* path = getenv("PATH");
        if (path) {
            std::stringstream ss(path);
            std::string dir;
            while (std::getline(ss, dir, ':')) {
                DIR* d = opendir(dir.c_str());
                if (d) {
                    struct dirent* entry;
                    while ((entry = readdir(d))) {
                        std::string name = entry->d_name;
                        if (name.find(text_str) == 0) {
                            std::string full_path = dir + "/" + name;
                            if (access(full_path.c_str(), X_OK) == 0) {
                                matches.push_back(name);
                            }
                        }
                    }
                    closedir(d);
                }
            }
        }

        glob_t glob_result;
        std::string pattern = text_str + "*";
        if (glob(pattern.c_str(), GLOB_TILDE, nullptr, &glob_result) == 0) {
            for (size_t i = 0; i < glob_result.gl_pathc; ++i) {
                std::string match = glob_result.gl_pathv[i];
                if (match.find(text_str) == 0) matches.push_back(match);
            }
            globfree(&glob_result);
        }
    }

    if (match_index < matches.size()) {
        return strdup(matches[match_index++].c_str());
    }
    return nullptr;
}

char** wsh_completion(const char* text, int start, int end) {
    rl_completion_append_character = ' ';
    rl_completion_suppress_append = 0;
    return rl_completion_matches(text, command_generator);
}

void setup_completer() {
    rl_bind_key('\t', rl_complete);
    rl_attempted_completion_function = wsh_completion;
    rl_completion_entry_function = command_generator;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, handle_signal);
    signal(SIGCHLD, handle_signal);
    variables["WELCOME"] = "Welcome to Well Shell (wsh)! Enjoy your session!";
    std::cout << COLOR_YELLOW << variables["WELCOME"] << COLOR_RESET << "\n";
    wsh_configure();
    if (argc > 1) {
        if (std::string(argv[1]) == "-c" && argc > 2) {
            std::map<std::string, std::string> local_vars;
            execute_line(std::string(argv[2]), local_vars);
            return 0;
        } else if (std::string(argv[1]) == "-e" && argc > 2) {
            execute_script(expand_tilde(argv[2]));
            return 0;
        }
    }
    wsh_loop();
    return 0;
}
