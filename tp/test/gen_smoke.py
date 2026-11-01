"""生成 tp/test/smoke.wll。

与 test_md_inline.wll 一致：用生成器产出，保证括号必然平衡。

用法：python gen_smoke.py
"""
import os

# 本脚本自身所在目录 —— 产物路径由它推导 ⇒ **不硬编码绝对路径**
# （CI 上仓库在别处，硬编码会写到错误位置）
HERE = os.path.dirname(os.path.abspath(__file__))

OUT = os.path.join(HERE, 'smoke.wll')

SRC = '''// tp/test/smoke.wll —— 工具链冒烟用例
//
// ⚠ 本文件由 tp/test/gen_smoke.py 生成 —— 请勿手改。
//
// 验收：D:\\wlwl_v0.12.1\\wlwl.exe run tp\\test\\smoke.wll  ⇒ 退出码 0
IMPORT("wlwl:std.test", ["TEST", "ASSERT", "ASSERT_EQ", "RUN_TESTS"]);

LET(body_arith, FUN(() ,
    (ASSERT_EQ(+(2, 3), 5));
    ASSERT(==(LEN("abc"), 3));
    TRUE));

LET(body_err, FUN(() ,
    (LET(r, +(1, ERR("boom"))));
    ASSERT(IS_ERR(r));
    ASSERT_EQ(UNWRAP_OR(r, -1), -1);
    TRUE));

TEST("smoke/arith", body_arith);
TEST("smoke/err_is_value", body_err);

LET(records, RUN_TESTS());
PRINT("smoke: ", LEN(records), " test(s) run");

LET MUT(failed, 0);
FOR(rec, records,
    (IF(AT_K(rec, "passed", FALSE),
        PRINT("  PASS ", AT_K(rec, "name", "?")),
        (SET(failed, +(failed, 1));
         PRINT("  FAIL ", AT_K(rec, "name", "?"))))));
PRINT("smoke: failed=", failed);

// ⚠ RUN_TESTS() 的失败**不影响退出码**（规范明载）⇒ 必须自己把关退出码，
// 否则「测试失败但 CI 绿」就会发生。
IF(>(failed, 0), (PRINT_ERR("smoke: FAILED"); PANIC("smoke failed")), NULL);
PRINT("smoke: OK");
'''


def main():
    open(OUT, 'w', encoding='utf-8', newline='\n').write(SRC)
    print(f'wrote {OUT} ({len(SRC)} chars)')


if __name__ == '__main__':
    main()
