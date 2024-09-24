import os
import asyncio

from readme import ReadMe
from updater import Updater
from filter import Filter

class ADBlock(object):
    def __init__(self):
        self.pwd = os.getcwd()

    async def refresh(self):
        readme = ReadMe(self.pwd + '/README.md')
        ruleList = readme.getRules()
        
        # 更新上游规则
        updater = Updater(ruleList)
        update, ruleList = await updater.update(self.pwd + '/rules')
        if not update:
            return

        # 生成新规则
        filter = Filter(ruleList, self.pwd + '/rules')
        filter.generate()

        # 生成 readme.md
        readme.setRules(ruleList)
        readme.regenerate()

async def main():
    adBlock = ADBlock()
    await adBlock.refresh()

if __name__ == '__main__':
    asyncio.run(main())