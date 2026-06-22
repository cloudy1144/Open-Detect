"""
混合数据集预处理脚本
合并 mal (24类) + USTC (20类) = 44 类
- mal 标签映射: 原始 0-23 → 全局 0-23 (不变)
- USTC 标签映射: 原始 0-19 → 全局 24-43
- 按类别分层采样，8:1:1 划分为 train/val/test
- 保存为 mixed_44_train.npz / mixed_44_val.npz / mixed_44_test.npz
"""

import numpy as np
from sklearn.model_selection import train_test_split
import os

DATASET_DIR = os.path.join(os.path.dirname(__file__), 'dataset')

MAL_TRAIN = os.path.join(DATASET_DIR, 'mal_32_1c_train.npz')
MAL_TEST = os.path.join(DATASET_DIR, 'mal_32_1c_test.npz')
USTC_TRAIN = os.path.join(DATASET_DIR, 'USTC_1c_train.npz')
USTC_TEST = os.path.join(DATASET_DIR, 'USTC_1c_test.npz')

OUT_TRAIN = os.path.join(DATASET_DIR, 'mixed_44_train.npz')
OUT_VAL = os.path.join(DATASET_DIR, 'mixed_44_val.npz')
OUT_TEST = os.path.join(DATASET_DIR, 'mixed_44_test.npz')

MAL_CLASSES = 24   # mal labels: 0-23
USTC_CLASSES = 20  # USTC labels: 0-19 (will be shifted to 24-43)
TOTAL_CLASSES = MAL_CLASSES + USTC_CLASSES  # 44

# 划分比例
TRAIN_RATIO = 0.8
VAL_RATIO = 0.1
TEST_RATIO = 0.1

SEED = 2022


def load_npz(path):
    d = np.load(path)
    return d['data'], d['target']


def main():
    print("=" * 60)
    print("加载原始数据集...")

    # 加载 mal 数据 (train + test)
    mal_train_data, mal_train_targets = load_npz(MAL_TRAIN)
    mal_test_data, mal_test_targets = load_npz(MAL_TEST)
    print(f"  mal train: {mal_train_data.shape}, labels: {np.unique(mal_train_targets)}")
    print(f"  mal test:  {mal_test_data.shape}, labels: {np.unique(mal_test_targets)}")

    # 加载 USTC 数据 (train + test)
    ustc_train_data, ustc_train_targets = load_npz(USTC_TRAIN)
    ustc_test_data, ustc_test_targets = load_npz(USTC_TEST)
    print(f"  USTC train: {ustc_train_data.shape}, labels: {np.unique(ustc_train_targets)}")
    print(f"  USTC test:  {ustc_test_data.shape}, labels: {np.unique(ustc_test_targets)}")

    # 合并 mal 全部数据 (标签不变: 0-23)
    mal_data = np.concatenate([mal_train_data, mal_test_data], axis=0)
    mal_targets = np.concatenate([mal_train_targets, mal_test_targets], axis=0)
    print(f"\n  mal 合并: {mal_data.shape[0]} 样本, labels: {mal_targets.min()} ~ {mal_targets.max()}")

    # 合并 USTC 全部数据，标签偏移 +24
    ustc_data = np.concatenate([ustc_train_data, ustc_test_data], axis=0)
    ustc_targets_raw = np.concatenate([ustc_train_targets, ustc_test_targets], axis=0)
    ustc_targets = ustc_targets_raw + MAL_CLASSES  # 24-43
    print(f"  USTC 合并: {ustc_data.shape[0]} 样本, labels: {ustc_targets.min()} ~ {ustc_targets.max()}")

    # 合并全部数据
    all_data = np.concatenate([mal_data, ustc_data], axis=0)
    all_targets = np.concatenate([mal_targets, ustc_targets], axis=0)
    print(f"\n  总计: {all_data.shape[0]} 样本, {TOTAL_CLASSES} 类")
    print(f"  labels: {np.unique(all_targets)}")

    # 对每个类别按 8:1:1 分层划分
    print("\n" + "=" * 60)
    print("按类别分层 8:1:1 划分...")

    train_data_list, train_targets_list = [], []
    val_data_list, val_targets_list = [], []
    test_data_list, test_targets_list = [], []

    for cls in range(TOTAL_CLASSES):
        mask = all_targets == cls
        cls_data = all_data[mask]
        cls_targets = all_targets[mask]
        n = len(cls_data)

        if n < 3:
            # 样本极少的类别，全放入 train
            print(f"  Class {cls}: {n} samples (too few, all -> train)")
            train_data_list.append(cls_data)
            train_targets_list.append(cls_targets)
            continue

        # 先分出 test (10%)
        train_val_data, test_data_cls, train_val_targets, test_targets_cls = train_test_split(
            cls_data, cls_targets, test_size=TEST_RATIO, random_state=SEED, stratify=cls_targets
        )

        # 再从 train_val 中分出 val (10% of total ≈ 1/9 of remaining)
        val_size = VAL_RATIO / (TRAIN_RATIO + VAL_RATIO)
        train_data_cls, val_data_cls, train_targets_cls, val_targets_cls = train_test_split(
            train_val_data, train_val_targets, test_size=val_size, random_state=SEED, stratify=train_val_targets
        )

        print(f"  Class {cls:2d}: total={n:5d}  train={len(train_data_cls):5d}  val={len(val_data_cls):5d}  test={len(test_data_cls):5d}")

        train_data_list.append(train_data_cls)
        train_targets_list.append(train_targets_cls)
        val_data_list.append(val_data_cls)
        val_targets_list.append(val_targets_cls)
        test_data_list.append(test_data_cls)
        test_targets_list.append(test_targets_cls)

    # 合并并打乱
    train_data_all = np.concatenate(train_data_list, axis=0)
    train_targets_all = np.concatenate(train_targets_list, axis=0)
    val_data_all = np.concatenate(val_data_list, axis=0)
    val_targets_all = np.concatenate(val_targets_list, axis=0)
    test_data_all = np.concatenate(test_data_list, axis=0)
    test_targets_all = np.concatenate(test_targets_list, axis=0)

    # 全量打乱
    rng = np.random.RandomState(SEED)
    for arr1, arr2 in [(train_data_all, train_targets_all),
                        (val_data_all, val_targets_all),
                        (test_data_all, test_targets_all)]:
        idx = rng.permutation(len(arr1))
        arr1[:] = arr1[idx]
        arr2[:] = arr2[idx]

    print("\n" + "=" * 60)
    print("保存 npz 文件...")

    os.makedirs(DATASET_DIR, exist_ok=True)
    np.savez(OUT_TRAIN, data=train_data_all, target=train_targets_all)
    np.savez(OUT_VAL, data=val_data_all, target=val_targets_all)
    np.savez(OUT_TEST, data=test_data_all, target=test_targets_all)

    print(f"  Train: {train_data_all.shape}, labels: {train_targets_all.min()} ~ {train_targets_all.max()}")
    print(f"  Val:   {val_data_all.shape}, labels: {val_targets_all.min()} ~ {val_targets_all.max()}")
    print(f"  Test:  {test_data_all.shape}, labels: {test_targets_all.min()} ~ {test_targets_all.max()}")

    total = len(train_data_all) + len(val_data_all) + len(test_data_all)
    print(f"\n  Train ratio: {len(train_data_all)/total:.3f}")
    print(f"  Val ratio:   {len(val_data_all)/total:.3f}")
    print(f"  Test ratio:  {len(test_data_all)/total:.3f}")

    print("\n" + "=" * 60)
    print("完成！文件已保存至:")
    print(f"  {OUT_TRAIN}")
    print(f"  {OUT_VAL}")
    print(f"  {OUT_TEST}")


if __name__ == '__main__':
    main()
