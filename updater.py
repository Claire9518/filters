import os
import time
import hashlib
import asyncio
from typing import List,Tuple

import httpx
from loguru import logger

from readme import Rule

# 上游规则更新
class Updater(object):
    def __init__(self, ruleList:List[Rule]):
        self.ruleList = ruleList
        self.isNeedUpdate = False

    async def update(self, path: str) -> Tuple[bool, List[Rule]]:
        taskList = []
        for rule in self.ruleList:
            logger.info(f"updating {rule.name}...")
            taskList.append(self.__Download(rule, path))
        
        results = await asyncio.gather(*taskList, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Task failed: {result}")
            else:
                new: Rule = result
                for rule in self.ruleList:
                    if new.name == rule.name:
                        rule.latest = new.latest
                        rule.update = new.update
                        if rule.update:
                            self.isNeedUpdate = True
                        break
        
        return self.isNeedUpdate, self.ruleList

    def __CalcFileSha256(self, filename):
        with open(filename, "rb") as f:
            sha256obj = hashlib.sha256()
            sha256obj.update(f.read())
            hash_value = sha256obj.hexdigest()
            return hash_value
        
    def __isConfigFile(self, filename):
        filestats = os.stat(filename)
        if filestats.st_size < 1024 * 4:
            return False
        return True

    async def __Download(self, rule: Rule, path: str) -> Rule:
        fileName = os.path.join(path, rule.filename)
        fileName_download = fileName + '.download'
        try:
            if os.path.exists(fileName_download):
                os.remove(fileName_download)

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(rule.url)
                response.raise_for_status()
                with open(fileName_download, 'wb') as f:
                    f.write(response.content)
            
            if not self.__isConfigFile(fileName_download):
                raise Exception("not rule file")

            if os.path.exists(fileName):
                sha256Old = self.__CalcFileSha256(fileName)
                sha256New = self.__CalcFileSha256(fileName_download)
                if sha256New != sha256Old:
                    rule.update = True
                os.remove(fileName)
            else:
                rule.update = True

            os.rename(fileName_download, fileName)
        except Exception as e:
            logger.error(f'{rule.name} download failed: {e}')
            raise  # 重新抛出异常，让 asyncio.gather 捕获
        finally:
            if rule.update:
                rule.latest = time.strftime("%Y/%m/%d", time.localtime())
            logger.info(f"{rule.name}: latest={rule.latest}, update={rule.update}")
            return rule
        
# 使用方法
async def main():
    rules = [Rule(...), Rule(...)]  # 初始化你的规则列表
    updater = Updater(rules)
    is_updated, updated_rules = await updater.update("/path/to/save")
    print(f"Need update: {is_updated}")
    for rule in updated_rules:
        print(f"Rule: {rule.name}, Latest: {rule.latest}, Updated: {rule.update}")

if __name__ == "__main__":
    asyncio.run(main())