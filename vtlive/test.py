#!/usr/bin/python

import json
import yaml


def formatjson():
    with open("tempvtlive.json", "r") as f:
        output = []
        for line in f:
            line = line.strip()
            #print (line)
            newline = yaml.safe_load(line)
            #print (newline)
            output.append(newline)

    with open("vtlivefeed.json", "w") as out:
        out.write(json.dumps(output))
        


def main():
    formatjson()

if __name__ == '__main__':
  main()

