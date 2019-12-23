#include "pch.h"
#include "SignatureFile.h"
#include "Util.h"
#include "json11/json11.hpp"
#include <sstream>
#include <fstream>
#include <iomanip>
#include "Signature.h"


static json11::Json s_json;


static bool GetJsonAddress(std::map<std::string, json11::Json>& addressMap, const std::string& moduleName, duint& address)
{
	for (auto& kv : addressMap) {
		auto& name = kv.first;
		if (_stricmp(name.c_str(), moduleName.c_str()) == 0) {
			auto& strAddress = kv.second.string_value();
			if (strAddress == "deleted") {
				address = 0;
				return true;
			}
			std::size_t idx;
			try {
				int d = std::stoi(strAddress, &idx, 0);
				address = idx == strAddress.size() ? d : 0;
			}
			catch (const std::invalid_argument & e) {
				_plugin_logprintf("invalid argument error in std::stoi()\n");
				if (e.what()) {
					_plugin_logprintf(e.what());
				}
				_plugin_logprintf(strAddress.c_str());
				_plugin_logprintf("\n");
				address = 0;
			}
			catch (const std::out_of_range & e) {
				_plugin_logprintf("out of range error in std::stoi()\n");
				if (e.what()) {
					_plugin_logprintf(e.what());
				}
				_plugin_logprintf(strAddress.c_str());
				_plugin_logprintf("\n");
				address = 0;
			}
			return true;
		}
	}
	return false;
}


static bool GetJsonAddress(json11::Json& json, const std::string& moduleName, duint& address)
{
	auto addressMap = json["address"].object_items();
	return GetJsonAddress(addressMap, moduleName, address);
}


static void SetJsonAddress(std::map<std::string, json11::Json>& addressMap, const std::string& moduleName, duint address)
{
	std::ostringstream oss;
	if (address == 0) {
		oss << "deleted";
	}
	else {
		oss << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(8) << address;
	}

	for (auto& kv : addressMap) {
		auto& name = kv.first;
		if (_stricmp(name.c_str(), moduleName.c_str()) == 0) {
			addressMap.insert_or_assign(name, oss.str());
			return;
		}
	}
	addressMap.insert_or_assign(moduleName, oss.str());
}


static void SetJsonAddress(json11::Json& json, const std::string& moduleName, duint address)
{
	auto jsonMap = json.object_items();
	auto addressMap = json["address"].object_items();
	SetJsonAddress(addressMap, moduleName, address);
	jsonMap.insert_or_assign("address", json11::Json(addressMap));
	json = json11::Json(jsonMap);
}


static void EraseJsonAddress(std::map<std::string, json11::Json>& addressMap, const std::string& moduleName)
{
	for (auto it = addressMap.begin(); it != addressMap.end(); ++it) {
		const std::string& name = it->first;
		if (_stricmp(name.c_str(), moduleName.c_str()) == 0) {
			addressMap.erase(it);
			break;
		}
	}
}

static void EraseJsonAddress(json11::Json& json, const std::string& moduleName)
{
	auto addressMap = json["address"].object_items();
	EraseJsonAddress(addressMap, moduleName);
	auto jsonMap = json.object_items();
	if (addressMap.size() == 0) {
		jsonMap.erase("address");
	}
	else {
		jsonMap.insert_or_assign("address", json11::Json(addressMap));
	}
	json = json11::Json(jsonMap);
}



namespace Signature::File
{
	bool Open(char* Path)
	{
		using json11::Json;

		duint mainModBase = Script::Module::GetMainModuleBase();
		std::string mainModName = Util::GetModName(mainModBase);

		std::ifstream ifs(Path);
		if (!ifs.is_open()) {
			_plugin_logprintf("cannot open the file: \"%s\"\n", Path);
			return false;
		}

		const std::string jsonText{ std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>() };
		ifs.close();

		std::string err;
		s_json = Json::parse(jsonText, err);
		if (err.size() > 0) {
			_plugin_logprintf("Unable to parse JSON: \"%s\"\n", Path);
			_plugin_logprintf("%s\n", err.c_str());
			return false;
		}

		Signature::Clear();

		size_t fromCache = 0;
		size_t match = 0;
		size_t missing = 0;
		size_t manyMatch = 0;
		size_t duplicate = 0;

		for (auto& obj : s_json.array_items()) {
			const std::string& label = obj["label"].string_value();
			std::string signature = obj["signature"].string_value();
			if (label.size() == 0) {
				continue;
			}

			duint rva = 0;
			if (GetJsonAddress((Json)obj, mainModName, rva)) {
				if (rva == 0) {
					continue;		// deleted
				}
			}

			if (rva) {
				// すでにアドレス取得済み
				fromCache++;
			}
			else {
				// search
				std::vector<duint> result;
				if (Signature::Find(signature, result, 2)) {
					if (result.size() == 0) {
						// 検索に失敗
						missing++;
						_plugin_logprintf("do not match signature\n");
						_plugin_logprintf("    label:     \"%s\"\n", label.c_str());
						_plugin_logprintf("    signature: \"%s\"\n", signature.c_str());
					}
					else {
						rva = result.front() - mainModBase;
						if (result.size() == 1) {
							// シグネチャからアドレス取得成功
							match++;
						}
						else {
							// 取得には成功したものの、複数マッチしている
							manyMatch++;
							_plugin_logprintf("too many match signature\n");
							_plugin_logprintf("    label:     \"%s\"\n", label.c_str());
							_plugin_logprintf("    signature: \"%s\"\n", signature.c_str());
						}
					}
				}
			}

			if (rva) {
				Util::SetLabel(label, mainModBase + rva);
			}
			if (Signature::Get(label)) {
				// 同じラベルに複数のシグネチャが付いている
				// .jsonファイルがおかしいので直接編集する必要があるかも
				duplicate++;
				_plugin_logprintf("<warning> duplicate entry: \"%s\"\n", label.c_str());
			}
			else {
				Signature::Set(label, signature);
			}
		}

		// 結果を表示
		_plugin_logprint("[ SECUNDA MOON -> Open ]");
		if (fromCache) {
			_plugin_logprintf("   cache:%d", fromCache);
		}
		if (match) {
			_plugin_logprintf("   match:%d", match);
		}
		if (missing) {
			_plugin_logprintf("   missing:%d", missing);
		}
		if (manyMatch) {
			_plugin_logprintf("   too many match:%d", manyMatch);
		}
		if (duplicate) {
			_plugin_logprintf("   duplicate entry:%d", duplicate);
		}
		_plugin_logprint("\n");

		return true;
	}


	bool Save(char* Path)
	{
		using json11::Json;

		duint mainModBase = Script::Module::GetMainModuleBase();
		std::string mainModName = Util::GetModName(mainModBase);
		if (mainModName.size() == 0) {
			_plugin_logprint("invalid module name");
			return false;
		}

		std::ofstream ofs(Path);
		if (!ofs.is_open()) {
			_plugin_logprint("cannot create json file");
			return false;
		}

		std::vector<Json> entries = s_json.array_items();

		// 削除されたシグネチャを処理
		for (Json& json : entries) {
			const std::string& label = json["label"].string_value();
			if (!Signature::Get(label)) {
				// アドレス欄に"deleted"をセット
				SetJsonAddress(json, mainModName, 0);
			}
		}

		Signature::ForEach([mainModBase, &entries, &mainModName] (const std::string& label, const std::string& signature)
			-> void {

			auto it = std::find_if(entries.begin(), entries.end(), [&label](const Json& json) -> auto {
				return label == json["label"].string_value();
			});
			if (it == entries.end()) {
				entries.push_back(Json({
					{ "label", label },
					{ "signature", signature }
					}));
				it = entries.end() - 1;
			}

			duint addr;
			if (!Script::Label::FromString(label.c_str(), &addr)) {
				EraseJsonAddress(*it, mainModName);
			}
			else {
				SetJsonAddress(*it, mainModName, addr - mainModBase);
			}

			auto jsonMap = it->object_items();
			jsonMap["signature"] = Json(signature);
			*it = Json(jsonMap);
		});

		s_json = Json(entries);
		ofs << s_json.dump();
		ofs.close();

		return true;
	}
}