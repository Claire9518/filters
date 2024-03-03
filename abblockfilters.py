import os
import re
import time

from downloader import Downloader
from resolver import Resolver

class Rule(object):
    def __init__(self, name, url):
        self.Name = name
        self.FileName = self.Name.replace(' ', '_') + '.txt'
        self.URL = url
        self.Downloader = Downloader(os.getcwd() + '/rules/' + self.FileName, self.URL)

    def Update(self):
        if self.Downloader.Download():
            return True
        return False

def GetRuleList(fileName):
    ruleList = []
    with open(fileName, "r") as f:
        for line in f:
            line = line.replace('\r', '').replace('\n', '')
            if line.find('|')==0 and line.rfind('|')==len(line)-1:
                rule = list(map(lambda x: x.strip(), line[1:].split('|')))
                if rule[2].find('(') > 0 and rule[2].find(')') > 0 and len(rule) > 4:
                    url = rule[2][rule[2].find('(')+1:rule[2].find(')')]
                    matchObj1 = re.match('(http|https):\/\/[\w\-_]+(\.[\w\-_]+)+([\w\-\.,@?^=%&:/~\+#]*[\w\-\@?^=%&/~\+#])?', url)
                    if matchObj1:
                        ruleList.append([rule[0], rule[1], url, rule[4]])
    return ruleList

def CreatReadme(ruleList, fileName):
    if os.path.exists(fileName):
        os.remove(fileName)
    
    with open(fileName, 'a') as f:
        f.write("# AdBlock DNS Filters\n")
        f.write("适用于AdGuard的去广告合并规则，每12个小时更新一次。\n")
        f.write("## 订阅链接\n")
        f.write("1. AdGuard Home 等DNS拦截服务使用规则1\n")
        f.write("2. AdGuard 等浏览器插件使用规则1 + 规则2\n\n")
        f.write("| 规则 | 原始链接 | 加速链接 | \n")
        f.write("|:-|:-|:-|\n")
        f.write("| 规则1：DNS 拦截 | [原始链接](https://raw.githubusercontent.com/Claire9518/filters/main/rules/adblockdns.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/Claire9518/filters/main/rules/adblockdns.txt)  |\n")
        f.write("| 规则2：插件拦截 | [原始链接](https://raw.githubusercontent.com/Claire9518/filters/main/rules/adblockfilters.txt) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/Claire9518/filters/main/rules/adblockfilters.txt) |\n")
        f.write("## 规则源\n")
        f.write("\n")
        f.write("| 规则 | 类型 | 原始链接 | 加速链接 |  更新日期 |\n")
        f.write("|:-|:-|:-|:-|:-|\n")
        for rule in ruleList:
            f.write("| %s | %s | [原始链接](%s) | [加速链接](https://mirror.ghproxy.com/https://raw.githubusercontent.com/Claire9518/filters/main/rules/%s.txt) | %s |\n" % (rule[0],rule[1],rule[2],rule[0].replace(' ', '_'),rule[3]))


def GetBlackList():
    blackList = []
    fileName = os.getcwd() + "/rules/black.txt"
    if os.path.exists(fileName):
        with open(fileName, 'r') as f:
            blackList = f.readlines()
            blackList = list(map(lambda x: x.replace("\n", ""), blackList))
    return blackList

def GetWhiteList():
    whiteList = []
    fileName = os.getcwd() + "/rules/white.txt"
    if os.path.exists(fileName):
        with open(fileName, 'r') as f:
            whiteList = f.readlines()
            whiteList = list(map(lambda x: x.replace("\n", ""), whiteList))
    return whiteList

# 去重、排序
def sort(domainDict, isBlock, blackList, whiteList):
    def repetition(l):
        tmp = []
        for i in l:
            for j in l:
                if len(i) > len(j) and i.rfind("." + j) == len(i) - len(j) - 1:
                    tmp.append(i)
                    break
        return list(set(l)-set(tmp))
    
    total = len(domainDict)
    processed = 0

    start = time.time()

    blockList = []
    blockList_all = []
    fldList = []
    for item in domainDict:
        fldList.append(item)
    fldList.sort() # 排序
    for fld in fldList:
        subdomainList = list(set(domainDict[fld])) # 去重
        if '' in subdomainList and fld not in whiteList: # 二级域名已被拦截，则干掉所有子域名
            subdomainList = ['']
        subdomainList = list(filter(None, subdomainList)) # 去空
        if len(subdomainList) > 0:
            if len(subdomainList) > 2:
                subdomainList = repetition(subdomainList) # 短域名已被拦截，则干掉所有长域名。如'a.example'、'b.example'、'example'，则只保留'example'
            subdomainList.sort() # 排序
            for subdomain in subdomainList:
                item = "%s.%s"%(subdomain, fld)
                if isBlock:
                    blockList_all.append("||%s^"%(item))
                else:
                    blockList_all.append("@@||%s^"%(item))
                
                if item not in blackList and item not in whiteList:
                    if isBlock:
                        blockList.append("||%s^"%(item))
                    else:
                        blockList.append("@@||%s^"%(item))
        else:
            item = "%s"%(fld)
            if isBlock:
                blockList_all.append("||%s^"%(item))
            else:
                blockList_all.append("@@||%s^"%(item))
            
            if item not in blackList and item not in whiteList:
                if isBlock:
                    blockList.append("||%s^"%(item))
                else:
                    blockList.append("@@||%s^"%(item))
                    
        processed += 1

        if processed % 1000 == 0:
            current = time.time()
            used = current - start
            remaining = used / processed * (total - processed) 
            
            hours_used = int(used / 3600)
            minutes_used = int((used % 3600) / 60)
            seconds_used = int((used % 60))
            
            hours_remaining = int(remaining / 3600)
            minutes_remaining = int((remaining % 3600) / 60)
            seconds_remaining = int((remaining % 60))
        
            print(f"Processed {processed}/{total}, "
                f"Time used: {hours_used}h {minutes_used}m {seconds_used}s, "
                f"Remaining: {hours_remaining}h {minutes_remaining}m {seconds_remaining}s")

    print(f"Sort completed, processed {processed} items")
    
    return blockList,blockList_all

def CreatDNS(blockDict, unblockDict, fileName):
    blackList = GetBlackList()
    whiteList = GetWhiteList()
    blockList,blockList_all = sort(blockDict, True, blackList, whiteList)
    unblockList,unblockList_all = sort(unblockDict, False, blackList, whiteList)
    
    # 备份全量域名，用于检查域名有效性生成黑名单

    backupName = fileName[:-len("txt")] + "backup"
    if os.path.exists(backupName):
        os.remove(backupName)
    with open(backupName, 'a') as f:
        for fiter in blockList_all:
            f.write("%s\n"%(fiter))
        for fiter in unblockList_all:
            f.write("%s\n"%(fiter))

    # 生成规则文件

    if os.path.exists(fileName):
        os.remove(fileName)
    
    with open(fileName, 'a') as f:
        f.write("!\n")
        f.write("! Title: My AdBlock DNS-Claire\n")
        f.write("! Description: 适用于AdGuard的去广告合并规则，每12个小时更新一次。\n")
        f.write("! Homepage: https://github.com/Claire9518/filters\n")
        f.write("! Source: https://raw.githubusercontent.com/Claire9518/filters/main/rules/adblockdns.txt\n")
        f.write("! Version: %s\n"%(time.strftime("%Y%m%d%H%M%S", time.localtime())))
        f.write("! Last modified: %s\n"%(time.strftime("%Y/%m/%d %H:%M:%S", time.localtime())))
        f.write("! Blocked domains: %s\n"%(len(blockList)))
        f.write("! unBlocked domains: %s\n"%(len(unblockList)))
        f.write("!\n")
        for fiter in blockList:
            f.write("%s\n"%(fiter))
        for fiter in unblockList:
            f.write("%s\n"%(fiter))

def CreatFiter(filterList, fileName):
    # 去重、排序
    def sort(L):
        L = list(set(L))
        L.sort()
        return L

    filterList = sort(filterList)

    if os.path.exists(fileName):
        os.remove(fileName)
    
    with open(fileName, 'a') as f:
        f.write("!\n")
        f.write("! Title: My AdBlock Filter-Claire\n")
        f.write("! Description: 适用于AdGuard的去广告合并规则，每12个小时更新一次。\n")
        f.write("! Homepage: https://github.com/Claire9518/filters\n")
        f.write("! Source: https://raw.githubusercontent.com/Claire9518/filters/main/rules/adblockfilters.txt\n")
        f.write("! Version: %s\n"%(time.strftime("%Y%m%d%H%M%S", time.localtime())))
        f.write("! Last modified: %s\n"%(time.strftime("%Y/%m/%d %H:%M:%S", time.localtime())))
        f.write("! Blocked Filters: %s\n"%(len(filterList)))
        f.write("!\n")
        for fiter in filterList:
            f.write("%s\n"%(fiter))

def Entry():
    def dictadd(d1, d2):
        d3 = dict()
        for item in d1:
            d3[item] = d1[item]
            if item in d2:
                d3[item] += d2[item]
        for item in d2:
            if item not in d1:
                d3[item] = d2[item]
        return d3
    pwd = os.getcwd()
    ruleFile = pwd + '/README.md'

    ruleList = GetRuleList(ruleFile)

    isUpdate = False
    lastUpdate = time.strftime("%Y/%m/%d", time.localtime())
    for i in range(0, len(ruleList)):
        relue = Rule(ruleList[i][0], ruleList[i][2])
        if relue.Update():
            isUpdate = True
            ruleList[i][3] = lastUpdate 
    
    if isUpdate:
        blockDict = dict()
        unblockDict = dict()
        filterList = []
        for i in range(0, len(ruleList)):
            resolver = Resolver(os.getcwd() + '/rules/' + ruleList[i][0].replace(' ', '_') + '.txt')
            d1, d2, l3 = resolver.Resolve(ruleList[i][1])
            print('%s: block[%s],unblock[%s],filter[%s]'%(ruleList[i][0], len(d1), len(d2), len(l3)))
            blockDict = dictadd(blockDict, d1)
            unblockDict = dictadd(unblockDict, d2)
            filterList += l3

        # 生成合并规则
        CreatDNS(blockDict, unblockDict, pwd + '/rules/adblockdns.txt')
        CreatFiter(filterList, pwd + '/rules/adblockfilters.txt')

        # 更新README.md
    CreatReadme(ruleList, pwd + '/README.md')

if __name__ == '__main__':
    Entry()