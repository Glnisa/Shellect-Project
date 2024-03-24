//Gülnisa Yıldırım 76401, all parts of this project are implemented by me.
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <termios.h> // termios, TCSANOW, ECHO, ICANON
#include <unistd.h>
#include <fcntl.h>  
#include <time.h> 

const char *sysname = "Shellect";

#define MAX_ALIAS_SIZE 256
#define MAX_COMMAND_SIZE 1024
#define MAX_LINE_SIZE 1280 // alias + command

const char *PATH_ENV_VAR = "PATH"; //for path resolution

enum return_codes {
	SUCCESS = 0,
	EXIT = 1,
	UNKNOWN = 2,
};

struct command_t {
	char *name;
	bool background;
	bool auto_complete;
	int arg_count;
	char **args;
	char *redirects[3]; // in/out redirection
	struct command_t *next; // for piping
};

//this is for alias
typedef struct alias {
    char alias[MAX_ALIAS_SIZE];
    struct command_t command;

} alias_t;

alias_t aliases[MAX_ALIAS_SIZE]; // assuming max 256 aliases
int alias_count = 0;

/**
 * Retrieves a command associated with a given alias.
 * 
 * This function searches through a collection of aliases to find
 * a command that corresponds to given alias. If alias is found,
 * it returns a pointer to command associated with alias.
 * If alias is not found, it returns NULL.
 * 
 * @param alias The alias for which to find corresponding command.
 * @return A pointer to the command associated with given alias,
 *         or NULL if alias is not found.
 */
struct command_t *get_command_from_alias(char *alias) {
    for (int i = 0; i < alias_count; i++) { // Iterate over array of aliases
        if (strcmp(aliases[i].alias, alias) == 0) { // Check if current alias matches given alias
            return &aliases[i].command; // If a match is found, return a pointer to associated command
        }
    }
    return NULL;
} 

/**
 * Prints a command struct
 * @param struct command_t *
 */
void print_command(struct command_t *command) {
	int i = 0;
	printf("Command: <%s>\n", command->name);
	printf("\tIs Background: %s\n", command->background ? "yes" : "no");
	printf("\tNeeds Auto-complete: %s\n",command->auto_complete ? "yes" : "no");
	printf("\tRedirects:\n");

	for (i = 0; i < 3; i++) {
		printf("\t\t%d: %s\n", i, command->redirects[i] ? command->redirects[i] : "N/A");
	}

	printf("\tArguments (%d):\n", command->arg_count);

	for (i = 0; i < command->arg_count; ++i) {
		printf("\t\tArg %d: %s\n", i, command->args[i]);
	}

	if (command->next) {
		printf("\tPiped to:\n");
		print_command(command->next);
	}
}

/**
 * Release allocated memory of a command
 * @param  command [description]
 * @return         [description]
 */
int free_command(struct command_t *command) {
	if (command->arg_count) {
		for (int i = 0; i < command->arg_count; ++i)
			free(command->args[i]);
		free(command->args);
	}

	for (int i = 0; i < 3; ++i) {
		if (command->redirects[i])
			free(command->redirects[i]);
	}

	if (command->next) {
		free_command(command->next);
		command->next = NULL;
	}

	free(command->name);
	free(command);
	return 0;
}

/**
 * Show the command prompt
 * @return [description]
 */
int show_prompt(void) {
	char cwd[1024], hostname[1024];
	gethostname(hostname, sizeof(hostname));
	getcwd(cwd, sizeof(cwd));
	printf("%s@%s:%s %s$ ", getenv("USER"), hostname, cwd, sysname);
	return 0;
}

/**
 * Parse a command string into a command struct
 * @param  buf     [description]
 * @param  command [description]
 * @return         0
 */
int parse_command(char *buf, struct command_t *command) {

	const char *splitters = " \t"; // split at whitespace
	int index, len;
	len = strlen(buf);
    

	// trim left whitespace
	while (len > 0 && strchr(splitters, buf[0]) != NULL) {
		buf++;
		len--;
	}

	while (len > 0 && strchr(splitters, buf[len - 1]) != NULL) {
		// trim right whitespace
		buf[--len] = 0;
	}

	// auto-complete
	if (len > 0 && buf[len - 1] == '?') {
		command->auto_complete = true;
	}

	// background
	if (len > 0 && buf[len - 1] == '&') {
		command->background = true;
	}

	char *pch = strtok(buf, splitters);
	if (pch == NULL) {
		command->name = (char *)malloc(1);
		command->name[0] = 0;
	} else {
		command->name = (char *)malloc(strlen(pch) + 1);
		strcpy(command->name, pch);
	}

	command->args = (char **)malloc(sizeof(char *));

	int redirect_index;
	int arg_index = 0;
	char temp_buf[1024], *arg;

	while (1) {
		// tokenize input on splitters
		pch = strtok(NULL, splitters);
		if (!pch)
			break;
		arg = temp_buf;
		strcpy(arg, pch);
		len = strlen(arg);

		// empty arg, go for next
		if (len == 0) {
			continue;
		}

		// trim left whitespace
		while (len > 0 && strchr(splitters, arg[0]) != NULL) {
			arg++;
			len--;
		}

		// trim right whitespace
		while (len > 0 && strchr(splitters, arg[len - 1]) != NULL) {
			arg[--len] = 0;
		}

		// empty arg, go for next
		if (len == 0) {
			continue;
		}

		// piping to another command
		if (strcmp(arg, "|") == 0) {
			struct command_t *c = malloc(sizeof(struct command_t));
			int l = strlen(pch);
			pch[l] = splitters[0]; // restore strtok termination
			index = 1;
			while (pch[index] == ' ' || pch[index] == '\t')
				index++; // skip whitespaces

			parse_command(pch + index, c);
			pch[l] = 0; // put back strtok termination
			command->next = c;
			continue;
		}

		// background process
		if (strcmp(arg, "&") == 0) {
			// handled before
			continue;
		}

		// handle input redirection
		redirect_index = -1;
		if (arg[0] == '<') {
			redirect_index = 0;
		}

		if (arg[0] == '>') {
			if (len > 1 && arg[1] == '>') {
				redirect_index = 2;
				arg++;
				len--;
			} else {
				redirect_index = 1;
			}
		}

		if (redirect_index != -1) {
			// Parses next part of command line input, which is expected to be file name for redirection
			char *redirect_content = strtok(NULL, splitters);
			len = strlen(redirect_content);
			command->redirects[redirect_index] = malloc(len);
			// Copies file name into appropriate redirection array index in command structure
			strcpy(command->redirects[redirect_index], redirect_content);
			continue;
		}


		// normal arguments
		if (len > 2 &&((arg[0] == '"' && arg[len - 1] == '"') ||(arg[0] == '\'' && arg[len - 1] == '\''))){ // quote wrapped arg 
			arg[--len] = 0;
			arg++;
		}

		command->args =(char **)realloc(command->args, sizeof(char *) * (arg_index + 1));

		command->args[arg_index] = (char *)malloc(len + 1);
		strcpy(command->args[arg_index++], arg);
	}
	command->arg_count = arg_index;

	// increase args size by 2
	command->args = (char **)realloc(command->args, sizeof(char *) * (command->arg_count += 2));

	// shift everything forward by 1
	for (int i = command->arg_count - 2; i > 0; --i) {
		command->args[i] = command->args[i - 1];
	}

	// set args[0] as a copy of name
	command->args[0] = strdup(command->name);

	// set args[arg_count-1] (last) to NULL
	command->args[command->arg_count - 1] = NULL;

	return 0;
}

/**
 * Loads aliases from a file into aliases array.
 * 
 * This function reads a file named ".alias" located in the user's home directory.
 * Each line in file should contain an alias followed by command it represents.
 * The function parses each line, creates a command structure for each command,
 * and stores alias and command pair in global `aliases` array.
 */
void load_aliases(void) {
	
    char *home = getenv("HOME"); // Get the path to the user's home directory
    char alias_file[MAX_COMMAND_SIZE];

    sprintf(alias_file, "%s/.alias", home); // Construct the full path to the .alias file

    FILE *file = fopen(alias_file, "r"); // Open the .alias file for reading
    if (file == NULL) {
        return;
    }

    char line[MAX_LINE_SIZE];

    // clear aliases
    alias_count = 0;

    // Read each line from the file
    while (fgets(line, sizeof(line), file)) {
        char *alias = strtok(line, " ");
        char *command = strtok(NULL, "\n");

        struct command_t *c = malloc(sizeof(struct command_t)); // Allocate memory for a new command structure
        parse_command(command, c);

        strcpy(aliases[alias_count].alias, alias); // Copy alias into global aliases array and store command
        aliases[alias_count].command = *c;
        alias_count++;
    }

    fclose(file);
}

void prompt_backspace(void) {
	putchar(8); // go back 1
	putchar(' '); // write empty over
	putchar(8); // go back 1 again
}

/**
 * Prompt a command from the user
 * @param  buf      [description]
 * @param  buf_size [description]
 * @return          [description]
 */
int prompt(struct command_t *command) {
	size_t index = 0;
	char c;
	char buf[4096];
	static char oldbuf[4096];

	// tcgetattr gets the parameters of the current terminal
	// STDIN_FILENO will tell tcgetattr that it should write the settings
	// of stdin to oldt
	static struct termios backup_termios, new_termios;
	tcgetattr(STDIN_FILENO, &backup_termios);
	new_termios = backup_termios;
	// ICANON normally takes care that one line at a time will be processed
	// that means it will return if it sees a "\n" or an EOF or an EOL
	new_termios.c_lflag &=~(ICANON |ECHO); // Also disable automatic echo. We manually echo each char.
	// Those new settings will be set to STDIN
	// TCSANOW tells tcsetattr to change attributes immediately.
	tcsetattr(STDIN_FILENO, TCSANOW, &new_termios);

	show_prompt();
	buf[0] = 0;

	while (1) {
		c = getchar();
		// printf("Keycode: %u\n", c); // DEBUG: uncomment for debugging

		// handle tab
		if (c == 9) {
			buf[index++] = '?'; // autocomplete
			break;
		}

		// handle backspace
		if (c == 127) {
			if (index > 0) {
				prompt_backspace();
				index--;
			}
			continue;
		}

		if (c == 27 || c == 91 || c == 66 || c == 67 || c == 68) {
			continue;
		}

		// up arrow
		if (c == 65) {
			while (index > 0) {
				prompt_backspace();
				index--;
			}

			char tmpbuf[4096];
			printf("%s", oldbuf);
			strcpy(tmpbuf, buf);
			strcpy(buf, oldbuf);
			strcpy(oldbuf, tmpbuf);
			index += strlen(buf);
			continue;
		}

		putchar(c); // echo the character
		buf[index++] = c;
		if (index >= sizeof(buf) - 1)
			break;
		if (c == '\n') // enter key
			break;
		if (c == 4) // Ctrl+D
			return EXIT;
	}

	// trim newline from the end
	if (index > 0 && buf[index - 1] == '\n') {
		index--;
	}

	// null terminate string
	buf[index++] = '\0';

	strcpy(oldbuf, buf);

	parse_command(buf, command);

	// print_command(command); // DEBUG: uncomment for debugging

	// restore the old settings
	tcsetattr(STDIN_FILENO, TCSANOW, &backup_termios);
	return SUCCESS;
}

static int is_module_loaded(void) {
    return system("lsmod | grep mymodule > /dev/null") == 0;
}

int process_command(struct command_t *command);

int psvis_func(char **args) {
    // Check if necessary arguments are provided
    // Args[1] and args[2] are expected to be PID and output file name respectively
    if (args[1] == NULL || args[2] == NULL) {
        printf("Usage: psvis <PID> <output_file>\n");
        return 1;
    }
    //Check if kernel module is loaded
    if (!is_module_loaded()) {
        printf("Loading kernel module...\n");
        system("sudo insmod module/mymodule.ko");
    } else {
        printf("Kernel module is already loaded.\n");
    }
    //Command string to refresh kernel module with a specific PID
    char buff1[128];
    sprintf(buff1, "sudo dmesg -C; sudo rmmod mymodule; sudo insmod module/mymodule.ko pid=%d", atoi(args[1]));
    system(buff1);

    FILE *meta_data = fopen("metadata.txt", "w");
    // Generate a graph description in 'dot' format, saved into 'metadata.txt'
    system("echo \"digraph G {\n\" > metadata.txt; sudo dmesg | cut -d [ -f2- | cut -d ] -f2- | grep 'Start time' >> metadata.txt; echo \"}\n\" >> metadata.txt");
    fclose(meta_data);

    char buff2[128];
    // Command to convert graph description into a PNG image
    sprintf(buff2, "cat metadata.txt | dot -Tpng > %s.png", args[2]);
    system(buff2);

    return 0;
}

int psvis_func(char **args);

int main(void) {
	load_aliases(); //when shellect is started, it loads aliases
	
	while (1) {
		struct command_t *command = malloc(sizeof(struct command_t));

		// set all bytes to 0
		memset(command, 0, sizeof(struct command_t));

		int code;
		code = prompt(command);
		if (code == EXIT) {
			break;
		}

		code = process_command(command);
		if (code == EXIT) {
			break;
		}

		free_command(command);
	}
	printf("\n");
	return 0;
}

/**
 * Schedules an audio file to be played after a specified number of minutes.
 * 
 * This function calculates the future time by adding the specified minutes to the current time.
 * It then creates a temporary cron job file to schedule the audio playback using `mpg123`.
 * 
 * @param minutes The number of minutes after which the audio file should be played.
 * @param file_path The path to the audio file to be played.
 */
void schedule_audio_play(int minutes, const char* file_path) {
    // Get current time
    time_t now = time(NULL);
    struct tm new_time = *localtime(&now);

    // Add minutes to current time
    new_time.tm_min += minutes;

    // Normalize time struct (in case minutes addition overflowed)
    mktime(&new_time);

    
    FILE* tmp = fopen("/tmp/cronjob.txt", "w");
    if (tmp == NULL) {
        perror("Error opening temporary file");
        return;
    }

    // Set up cron job to run mpg123 at specified time
    printf("Scheduling audio play at %d:%d\n", new_time.tm_hour, new_time.tm_min);
    fprintf(tmp,"%d %d * * * XDG_RUNTIME_DIR=/run/user/$(id -u) DISPLAY=:0.0 mpg123 -q '%s'\n",new_time.tm_min, new_time.tm_hour, file_path);
    fclose(tmp);

    // Install new cron job by appending temporary file to current user's crontab
    system("crontab /tmp/cronjob.txt");

    // Remove temporary file
    system("rm /tmp/cronjob.txt");
}

int process_command(struct command_t *command) {
	int r;

	if (strcmp(command->name, "") == 0) {
		return SUCCESS;
	}

	if (strcmp(command->name, "exit") == 0) {
		return EXIT;
	}

	if (strcmp(command->name, "cd") == 0) {
		//since there are always 2 args, name and null changed this to be greater than 2
		if (command->arg_count > 2) {
			r = chdir(command->args[1]); //initially this was r = chdir(command->args[0]);, I think this is wrong so I changed it with 1
			if (r == -1) {
				printf("-%s: %s: %s\n", sysname, command->name,strerror(errno));
			}
			return SUCCESS;
		}
	}
	
	/**
 	* Handles 'alias' command in shell.
 	* 
 	* This saves a new alias to .alias file in user's home directory.
 	* If alias command is entered, it appends given alias and its corresponding
 	* command to .alias file and then reloads aliases to update shell's alias list.
 	* 
 	* @param command The command structure containing name 'alias' and its arguments.
 	* @return Returns SUCCESS if alias is successfully saved and reloaded, or UNKNOWN in case of an error.
 	*/
	if(strcmp(command->name, "alias")==0){

        //save given alias to .alias file in home directory
        char *home = getenv("HOME");

        char alias_file[MAX_COMMAND_SIZE];
        sprintf(alias_file, "%s/.alias", home);

        FILE *file = fopen(alias_file, "a");
        if (file == NULL) {
            printf("-%s: %s: %s\n", sysname, command->name,
                       strerror(errno));
            return UNKNOWN;
        }

        //print out all args to file
        for(int i = 1; i<command->arg_count-1; i++)
        {
            fprintf(file, "%s ", command->args[i]);
        }
        fprintf(file, "\n");

        fclose(file);

        //reload aliases
        load_aliases();

        return SUCCESS;
        }
	/**
 	* Handles the 'xxd' command in the shell.
 	* 
 	* This either reads from a specified file or from stdin and prints a hexadecimal
 	* dump of the input. It supports optional grouping of hexadecimal numbers.
 	* 
 	* @param command The command structure containing the name 'xxd' and its arguments.
 	* @return Returns SUCCESS after printing the hex dump, or UNKNOWN in case of an error.
 	*/
        if(strcmp(command->name, "xxd")==0){
        	int g = 1;
        	FILE *fp;
		// Check if correct number of arguments is given and set group size
        	if(command->arg_count==5 || command->arg_count==4){
            		g = atoi(command->args[2]);
            		if(g<=0){
                		printf("Group size is not valid\n");
                		return UNKNOWN;
            		}
            		fp = fopen(command->args[3], "r");
        	}
		// If no group size is specified, open file from second argument
        	else 
            		fp = fopen(command->args[1], "r");
        
        	if(g>16)
        		g=16;
        
		// If the file cannot be opened, read from stdin
        	if(fp==NULL){
            		char ch [4096];
            		int i = 0;
            		while(1){
                		ch[i] = getchar();
				// Break the loop if newline or EOF is encountered
                		if(ch[i]=='\n' || ch[i]==EOF){
                    			ch[i] = '\0';
                    			break;
                		}
                	i++;
            		}

            		// dump input as hex 
           		int total = 0;
            		int group = 0;
            		while(ch[total]!='\0'){
                		if(total%16==0){
                    			printf("\n%08x: ", total);
                    			group = 0;
                		}
                		if(group%g==0)
                			printf(" ");
                		printf("%02X", ch[total]);
                		total++;
                		group++;
            		}
            		printf("\n");
            		return SUCCESS;
        	}

        	char ch;
        	ch = fgetc(fp);
        	int total = 0;
        	int group = 0;
        	while(ch!=EOF){
	   		// Print offset at start of each line
            		if(total%16==0){
            			printf("\n%08x: ", total);
            			group = 0;
	    		}
            		if(group%g==0) printf(" "); // Print space for group separation
            		printf("%02X", ch); // Print the hex value of the character

            		total++;
            		group++;
            		ch = fgetc(fp); //Read next character
        	}
        	printf("\n");
        	fclose(fp);
        	return SUCCESS;
    }
  
    /**
 	* Handles 'good_morning' command in shell.
 	* 
 	* This function schedules an audio file to be played after a specified number of minutes.
 	* If required time argument is not provided, it prints an error message.
 	* 
 	* @param command The command structure containing name 'good_morning' and its arguments.
 	* @return Returns SUCCESS if audio is successfully scheduled or played immediately,or UNKNOWN in case of an invalid time argument.
 	*/
	if(strcmp(command->name,"good_morning")==0){
        //Check if correct number of arguments is given (including command name)
        if(command->arg_count==4){
            //Get time
            int time = atoi(command->args[1]);

            //Check if time is valid
            if(time<=0){
                printf("Time is not valid\n");
                return UNKNOWN;
            }

            //Schedule the audio file to play
            schedule_audio_play(time, command->args[2]);
            return SUCCESS;
        }
        else{
            // If required time argument is missing, print an error message
        	
            printf("Invalid arguments\n");
            return SUCCESS;
        }
    }

    if (strcmp(command->name, "moodmusic") == 0) {
        if (command->arg_count < 2) {
            printf("Usage: moodmusic <mood>\n");
            return SUCCESS;  // or return UNKNOWN;
        }

        char *mood = command->args[1];
        char command[256];

        if (strcmp(mood, "happy") == 0) {
            sprintf(command, "mpg123 /Users/gulnisa/github-classroom/KU-Comp304/project-1-shell-x/happy.mp3");
        } else if (strcmp(mood, "sad") == 0) {
            sprintf(command, "mpg123 /Users/gulnisa/github-classroom/KU-Comp304/project-1-shell-x/sad.mp3");
		 
        } else {
            printf("Mood not recognized. Available moods: happy, sad\n");
            return SUCCESS;  // or return UNKNOWN;
        }

        system(command);
        return SUCCESS;
    }
    struct command_t *c = get_command_from_alias(command->name);
    if(c!=NULL){
		// Check if command associated with alias has arguments
        if(c->arg_count>0){
            for(int i = 0; i<c->arg_count; i++){
                // Process the command associated with the alias
                return process_command(c);
            }
        }
    }
    if (strcmp(command->name, "psvis") == 0) {
		// Check if the number of arguments is more than two
		if (command->arg_count > 2) {
			psvis_func(command->args);
	        	return SUCCESS;
		} 
		else {
	        	printf("-%s: %s: Missing Arguments Caught\n", sysname, command->name);
	        	return UNKNOWN;
	    }
    }
	 

	pid_t pid = fork();
	// child
	if (pid == 0) {

	// If there is an input redirection specified for command (indicated with '<')
       	if (command->redirects[0] != NULL) {
			// If file exists, it redirects stdin to this file
			if (access(command->redirects[0], F_OK) != -1) {
				freopen(command->redirects[0], "r", stdin);
			} 
			else {
				printf("-%s: %s: %s\n", sysname, command->name,strerror(errno));
				exit(EXIT_FAILURE);
			}
		}
		// If there is an output redirection specified for command (indicated with '>')
		if (command->redirects[1] != NULL) {
			// It redirects stdout to specified file. If file does not exist, it is created
			freopen(command->redirects[1], "w", stdout);
		}
        // If there is an output append redirection specified for command (indicated with '>>')
		if (command->redirects[2] != NULL) {

			freopen(command->redirects[2], "a", stdout);
		}

		//check if command is in current directory
		if (access(command->name, F_OK) != -1) {
			char subcommand[256];

			strcpy(subcommand, command->name);

			//concat the arguments to command string
			for (int i = 1; i < command->arg_count - 1; i++) {
				strcat(subcommand, " ");
				strcat(subcommand, command->args[i]);
			}

			// Execute command using system function
			int status = system(subcommand);

			if (status == -1) {
				return EXIT;
			}
			if (WEXITSTATUS(status) != 0) {
				return UNKNOWN;
			}
			return SUCCESS;
		}
                // Retrieves PATH environment variable which contains directories to search for executable files
		char *path_var = getenv(PATH_ENV_VAR);
		if (path_var) {
			//Splits PATH environment variable into individual directories using ':' as a delimiter
			char *path = strtok(path_var, ":");
		    // Defines a buffer to hold full executable path
			char exec_path[1024];
			// Iterates through each directory in PATH variable
			while (path != NULL) {
				snprintf(exec_path, sizeof(exec_path), "%s/%s", path,command->name);
				execv(exec_path, command->args);
				path = strtok(NULL, ":");
			}
		}
		// If no valid path is found, print an error message
		printf("-%s: %s: command not found\n", sysname, command->name);
		exit(EXIT_FAILURE);
	} 
	else {
		// Background process implementation
		if (!command->background) {
			wait(0); // wait for child process to finish
		}
		else{
			printf("PID: %d\n", pid); // print the pid of the background process
		}
		return SUCCESS;
	}

	// TODO: your implementation here

	printf("-%s: %s: command not found\n", sysname, command->name);
	return UNKNOWN;
}
