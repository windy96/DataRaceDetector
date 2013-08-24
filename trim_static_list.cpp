#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>

using namespace std;

FILE	*fps, *fpd, *fpo;
char	line[200];
char	var[200];
unsigned long int	addr;
unsigned int		size;

vector<string> varList;
vector<string>::iterator it;

int		lineNum;


int main(int argc, char *argv[])
{
	if (argc < 4) {
		printf("[Usage] trim_static_list {variable info for static} {variable info for dynamic} {output file}\n\n");
		return -1;
	}

	// read variable info file for static executable
	fps = fopen(argv[1], "r");
	if (fps == NULL) {
		printf("Failed to open file %s\n", argv[1]);
		return -1;
	}

	// read variable info file for dynamic executable
	fpd = fopen(argv[2], "r");
	if (fpd == NULL) {
		printf("Failed to open file %s\n", argv[2]);
		return -1;
	}

	// open write variable info file
	fpo = fopen(argv[3], "w");
	if (fpo == NULL) {
		printf("Failed to open file %s\n", argv[3]);
		return -1;
	}

	lineNum = 0;
	while ( fgets(line, 200, fpd) )
	{
		lineNum++;
		sscanf(line, "%s %lx %x", &var, &addr, &size);
		varList.push_back(string(var));
	}
			
	lineNum = 0;
	while (fgets(line, 200, fps))
	{
		lineNum++;
		sscanf(line, "%s %lx %d", &var, &addr, &size);
		string s = string(var);

		for (it = varList.begin(); it != varList.end(); it++) {
			if (*it == s) {
				fprintf(fpo, "%s %lx %x\n", var, addr, size);
				varList.erase(it);
				break;
			}
		}
	}

	if (varList.size() != 0) {
		printf("varList is not empty\n");
		for (it = varList.begin(); it != varList.end(); it++) {
			printf("%s\n", (*it).c_str());
		}
	}


	fclose(fpd);
	fclose(fps);
	fclose(fpo);
 
}

