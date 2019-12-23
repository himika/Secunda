#pragma once

#include <functional>
#include <vector>


namespace Signature
{
	// ラベルlabelに対応するシグネチャが見つかればtrueを返す
	bool Get(const std::string& label);

	// ラベルlabelに対応するシグネチャが見つかればtrueを返し、引数signatureにセットする
	bool Get(const std::string& label, std::string& signature);

	// ラベルlabelに対応するシグネチャsignatureを登録する
	void Set(const std::string& label, const std::string& signature);

	// ラベルlabelに対応するシグネチャを削除する
	void Remove(const std::string& label);

	// 登録されたシグネチャの総数を返す
	size_t Size();

	// 登録されたシグネチャをすべて削除する
	void Clear();

	// 登録されたシグネチャを走査する
	void ForEach(std::function<void(const std::string& label, const std::string& signature)> callback);

	// シグネチャ文字列を、検索用のパターン文字列とインデックスに分解して返す
	bool MakePatternFromSignature(const std::string& signature, std::string& pattern, size_t& index);

	// シグネチャを検索し、見つかったアドレスを全て返す
	bool Find(const std::string& signature, std::vector<duint>& result, size_t maxResult = 0);

	// x64dbgのリファレンスビューにシグネチャ一覧を表示
	void Show();
}
