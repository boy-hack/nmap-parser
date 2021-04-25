import json
import re


def ParseNmap():
    filename = "nmap-service-probes"
    with open(filename, encoding="utf-8") as f:
        lines = f.readlines()

    probes = []
    probe = {}
    for line in lines:
        line = line.strip()
        if line == "":
            continue
        if line.startswith("#"):
            continue
        if line.startswith("Exclude "):
            continue

        if line.startswith("Probe "):
            if probe:
                probes.append(probe)
            probe = {
                "protocol": "",
                "probename": "",
                "probestring": "",
                "ports": [],
                "sslports": [],
                "totalwaitms": "",
                "tcpwrappedms": "",
                "rarity": "",
                "fallback": "",
                "matches": [],
                "softmatches": []
            }
            # get probe
            protocol = line[6:9]
            if protocol not in ["TCP", "UDP"]:
                raise Exception(protocol + " 不支持")
            probename_start = 10
            probename_end = line.index(" ", probename_start)
            if probename_end - probename_start <= 0:
                raise Exception("probename解析失败")
            probename = line[probename_start:probename_end]
            probestring_start = line.index("q|", probename_end) + 1
            probestring = line[probestring_start:].strip("|")
            probe["protocol"] = protocol
            probe["probename"] = probename
            probe["probestring"] = probestring

        elif line.startswith("match "):
            # Syntax: match <service> <pattern> [<versioninfo>]
            # match iperf3 m|^\t$|
            # softmatch quic m|^\r\x89\xc1\x9c\x1c\*\xff\xfc\xf1((?:Q[0-8]\d\d)+)$| i/QUIC versions$SUBST(1,"Q",", Q")/
            matchtext = line[len("match "):]
            index = matchtext.index(" m")
            m = matchtext[index + 2]  # 获取m后边的字符
            name = matchtext[:index]
            matchtext = matchtext[len(name):].strip()

            regx_start = 2
            regx_end = matchtext.index(m, regx_start)
            regx = matchtext[regx_start:regx_end]
            regx_flag = ""
            if regx_end + 1 < len(matchtext):
                regx_flag = matchtext[regx_end + 1].strip()
            dd = {
                "pattern": regx,
                "name": name,
                "pattern_flag": regx_flag,
                'versioninfo': {'cpename': "",
                                'devicetype': "",
                                'hostname': "",
                                'info': "",
                                'operatingsystem': "",
                                'vendorproductname': "",
                                'version': ""
                                }
            }
            matchtext = matchtext[regx_end:]

            regx_p = "(\w|cpe:)/(.*?)/"
            ll = re.findall(regx_p, matchtext)
            for w, content in ll:
                if w == "p":
                    dd["versioninfo"]["vendorproductname"] = content
                elif w == "v":
                    dd["versioninfo"]["version"] = content
                elif w == "i":
                    dd["versioninfo"]["info"] = content
                elif w == "h":
                    dd["versioninfo"]["hostname"] = content
                elif w == "o":
                    dd["versioninfo"]["operatingsystem"] = content
                elif w == "d":
                    dd["versioninfo"]["devicetype"] = content
                elif w == "cpe:":
                    dd["versioninfo"]["cpename"] = content
            probe["matches"].append(dd)



        elif line.startswith("softmatch "):
            matchtext = line[len("softmatch "):]
            index = matchtext.index(" m")
            m = matchtext[index + 2]  # 获取m后边的字符
            name = matchtext[:index]
            matchtext = matchtext[len(name):].strip()

            regx_start = 2
            regx_end = matchtext.index(m, regx_start)
            regx = matchtext[regx_start:regx_end]
            regx_flag = ""
            if regx_end + 1 < len(matchtext):
                regx_flag = matchtext[regx_end + 1].strip()
            dd = {
                "pattern": regx,
                "name": name,
                "pattern_flag": regx_flag,
                'versioninfo': {'cpename': "",
                                'devicetype': "",
                                'hostname': "",
                                'info': "",
                                'operatingsystem': "",
                                'vendorproductname': "",
                                'version': ""
                                }
            }
            matchtext = matchtext[regx_end:]

            regx_p = "(\w|cpe:)/(.*?)/"
            ll = re.findall(regx_p, matchtext)
            for w, content in ll:
                if w == "p":
                    dd["versioninfo"]["vendorproductname"] = content
                elif w == "v":
                    dd["versioninfo"]["version"] = content
                elif w == "i":
                    dd["versioninfo"]["info"] = content
                elif w == "h":
                    dd["versioninfo"]["hostname"] = content
                elif w == "o":
                    dd["versioninfo"]["operatingsystem"] = content
                elif w == "d":
                    dd["versioninfo"]["devicetype"] = content
                elif w == "cpe:":
                    dd["versioninfo"]["cpename"] = content
            probe["softmatches"].append(dd)


        elif line.startswith("ports "):
            ports = line[len("ports "):].split(",")
            probe["ports"] = ports

        elif line.startswith("sslports "):
            sslports = line[len("sslports "):].split(",")
            probe["sslports"] = sslports
        elif line.startswith("totalwaitms "):
            totalwaitms = line[len("totalwaitms "):]
            probe["totalwaitms"] = totalwaitms
        elif line.startswith("tcpwrappedms "):
            tcpwrappedms = line[len("tcpwrappedms "):]
            probe["totalwaitms"] = tcpwrappedms
        elif line.startswith("rarity "):
            rarity = line[len("rarity "):]
            probe["rarity"] = rarity
        elif line.startswith("fallback "):
            fallback = line[len("fallback "):]
            probe["fallback"] = fallback
        else:
            print("[x] ", line)
        # print(line)
    if probe:
        probes.append(probe)
    return probes


if __name__ == '__main__':
    mm = ParseNmap()
    with open("nmap.json", "w") as f:
        json.dump(mm, f, indent=4)
    # print(len(mm))
    # tongji = {
    #     "tcp": 0,
    #     "udp": 0
    # }
    # for i in mm:
    #     if i["protocol"] == "TCP":
    #         tongji["tcp"] += 1
    #     else:
    #         tongji["udp"] += 1
    # print(tongji)
