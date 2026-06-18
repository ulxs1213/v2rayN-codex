using System.Globalization;

namespace ServiceLib.Handler;

public static class SubscriptionHandler
{
    public static async Task UpdateProcess(Config config, string subId, bool blProxy, Func<bool, string, Task> updateFunc)
    {
        var updateMode = blProxy ? Global.ProxyTag : Global.DirectTag;
        Logging.SaveLog($"UpdateSubscription start ({updateMode}), scope={(subId.IsNotEmpty() ? "selected" : "all")}");
        await updateFunc?.Invoke(false, ResUI.MsgUpdateSubscriptionStart);
        var subItem = await AppManager.Instance.SubItems();

        if (subItem is not { Count: > 0 })
        {
            await updateFunc?.Invoke(false, ResUI.MsgNoValidSubscription);
            Logging.SaveLog($"UpdateSubscription end ({updateMode}), successCount=0, reason=no valid subscription");
            return;
        }

        var successCount = 0;
        var changedCount = 0;
        var unchangedCount = 0;
        foreach (var item in subItem)
        {
            try
            {
                if (!IsValidSubscription(item, subId))
                {
                    continue;
                }

                var hashCode = $"{item.Remarks}->";
                if (item.Enabled == false)
                {
                    await updateFunc?.Invoke(false, $"{hashCode}{ResUI.MsgSkipSubscriptionUpdate}");
                    continue;
                }

                // Create download handler
                var downloadHandle = CreateDownloadHandler(hashCode, updateFunc);
                await updateFunc?.Invoke(false, $"{hashCode}{ResUI.MsgStartGettingSubscriptions}");

                // Get all subscription content (main subscription + additional subscriptions)
                var result = await DownloadAllSubscriptions(config, item, blProxy, downloadHandle);

                // Process download result
                var beforeProfiles = await GetSubscriptionProfileSnapshot(item.Id);
                var importCount = await ProcessDownloadResult(config, item.Id, result, hashCode, updateFunc);
                if (importCount > 0)
                {
                    successCount++;
                    var afterProfiles = await GetSubscriptionProfileSnapshot(item.Id);
                    if (HasSubscriptionChanged(beforeProfiles, afterProfiles))
                    {
                        item.UpdateTime = DateTimeOffset.Now.ToUnixTimeSeconds();
                        await ConfigHandler.AddSubItem(config, item);
                        changedCount++;
                        await updateFunc?.Invoke(false, $"{hashCode}{FormatSubscriptionChangedMessage(beforeProfiles.Count, afterProfiles.Count)}");
                    }
                    else
                    {
                        unchangedCount++;
                        await updateFunc?.Invoke(false, $"{hashCode}{FormatSubscriptionUnchangedMessage()}");
                    }
                }

                await updateFunc?.Invoke(false, "-------------------------------------------------------");
            }
            catch (Exception ex)
            {
                var hashCode = $"{item.Remarks}->";
                Logging.SaveLog("UpdateSubscription", ex);
                await updateFunc?.Invoke(false, $"{hashCode}{ResUI.MsgFailedImportSubscription}: {ex.Message}");
                await updateFunc?.Invoke(false, "-------------------------------------------------------");
            }
        }

        if (successCount > 0)
        {
            await updateFunc?.Invoke(false, "正在刷新节点 IP 信息...");
            var ipInfoCount = await RefreshServerIPInfoAfterSubscriptionUpdate(config, blProxy);
            await updateFunc?.Invoke(false, $"已刷新节点 IP 信息: {ipInfoCount}");
        }

        await updateFunc?.Invoke(successCount > 0, $"{ResUI.MsgUpdateSubscriptionEnd}");
        Logging.SaveLog($"UpdateSubscription end ({updateMode}), successCount={successCount}, changedCount={changedCount}, unchangedCount={unchangedCount}");
    }

    private static async Task<List<string>> GetSubscriptionProfileSnapshot(string subId)
    {
        var profiles = await AppManager.Instance.ProfileItems(subId);
        if (profiles is not { Count: > 0 })
        {
            return [];
        }

        return profiles
            .Select(CreateProfileSnapshotHash)
            .OrderBy(t => t, StringComparer.Ordinal)
            .ToList();
    }

    private static string FormatSubscriptionChangedMessage(int beforeCount, int afterCount)
    {
        return IsChineseUi()
            ? $"订阅内容已变化，节点数量: {beforeCount}->{afterCount}"
            : $"Subscription content changed, profiles: {beforeCount}->{afterCount}";
    }

    private static string FormatSubscriptionUnchangedMessage()
    {
        return IsChineseUi()
            ? "订阅已获取，但节点内容没有变化，更新时间保持不变"
            : "Subscription fetched, but profile content was unchanged; update time kept";
    }

    private static bool IsChineseUi()
    {
        return CultureInfo.CurrentUICulture.Name.StartsWith("zh", StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasSubscriptionChanged(List<string> beforeProfiles, List<string> afterProfiles)
    {
        if (beforeProfiles.Count != afterProfiles.Count)
        {
            return true;
        }

        return !beforeProfiles.SequenceEqual(afterProfiles);
    }

    private static string CreateProfileSnapshotHash(ProfileItem item)
    {
        var protocolExtra = item.GetProtocolExtra();
        var transportExtra = item.GetTransportExtra();
        var snapshot = JsonUtils.Serialize(new
        {
            item.ConfigType,
            item.CoreType,
            Remarks = NormalizeSnapshotValue(item.Remarks),
            Address = NormalizeSnapshotValue(item.Address),
            item.Port,
            Password = NormalizeSnapshotValue(item.Password),
            Username = NormalizeSnapshotValue(item.Username),
            Network = NormalizeSnapshotValue(item.Network),
            StreamSecurity = NormalizeSnapshotValue(item.StreamSecurity),
            AllowInsecure = NormalizeSnapshotValue(item.AllowInsecure),
            Sni = NormalizeSnapshotValue(item.Sni),
            Alpn = NormalizeSnapshotValue(item.Alpn),
            Fingerprint = NormalizeSnapshotValue(item.Fingerprint),
            PublicKey = NormalizeSnapshotValue(item.PublicKey),
            ShortId = NormalizeSnapshotValue(item.ShortId),
            SpiderX = NormalizeSnapshotValue(item.SpiderX),
            Mldsa65Verify = NormalizeSnapshotValue(item.Mldsa65Verify),
            item.MuxEnabled,
            Cert = NormalizeSnapshotValue(item.Cert),
            CertSha = NormalizeSnapshotValue(item.CertSha),
            EchConfigList = NormalizeSnapshotValue(item.EchConfigList),
            VerifyPeerCertByName = NormalizeSnapshotValue(item.VerifyPeerCertByName),
            Finalmask = NormalizeSnapshotValue(item.Finalmask),
            Protocol = new
            {
                protocolExtra.Uot,
                CongestionControl = NormalizeSnapshotValue(protocolExtra.CongestionControl),
                AlterId = NormalizeSnapshotValue(protocolExtra.AlterId),
                VmessSecurity = NormalizeSnapshotValue(protocolExtra.VmessSecurity),
                Flow = NormalizeSnapshotValue(protocolExtra.Flow),
                VlessEncryption = NormalizeSnapshotValue(protocolExtra.VlessEncryption),
                SsMethod = NormalizeSnapshotValue(protocolExtra.SsMethod),
                WgPublicKey = NormalizeSnapshotValue(protocolExtra.WgPublicKey),
                WgPresharedKey = NormalizeSnapshotValue(protocolExtra.WgPresharedKey),
                WgInterfaceAddress = NormalizeSnapshotValue(protocolExtra.WgInterfaceAddress),
                WgReserved = NormalizeSnapshotValue(protocolExtra.WgReserved),
                protocolExtra.WgMtu,
                SalamanderPass = NormalizeSnapshotValue(protocolExtra.SalamanderPass),
                protocolExtra.UpMbps,
                protocolExtra.DownMbps,
                Ports = NormalizeSnapshotValue(protocolExtra.Ports),
                HopInterval = NormalizeSnapshotValue(protocolExtra.HopInterval),
                protocolExtra.InsecureConcurrency,
                protocolExtra.NaiveQuic,
                GroupType = NormalizeSnapshotValue(protocolExtra.GroupType),
                ChildItems = NormalizeSnapshotValue(protocolExtra.ChildItems),
                SubChildItems = NormalizeSnapshotValue(protocolExtra.SubChildItems),
                Filter = NormalizeSnapshotValue(protocolExtra.Filter),
                protocolExtra.MultipleLoad
            },
            Transport = new
            {
                RawHeaderType = NormalizeSnapshotValue(transportExtra.RawHeaderType),
                Host = NormalizeSnapshotValue(transportExtra.Host),
                Path = NormalizeSnapshotValue(transportExtra.Path),
                XhttpMode = NormalizeSnapshotValue(transportExtra.XhttpMode),
                XhttpExtra = NormalizeSnapshotValue(transportExtra.XhttpExtra),
                GrpcAuthority = NormalizeSnapshotValue(transportExtra.GrpcAuthority),
                GrpcServiceName = NormalizeSnapshotValue(transportExtra.GrpcServiceName),
                GrpcMode = NormalizeSnapshotValue(transportExtra.GrpcMode),
                KcpHeaderType = NormalizeSnapshotValue(transportExtra.KcpHeaderType),
                KcpSeed = NormalizeSnapshotValue(transportExtra.KcpSeed),
                transportExtra.KcpMtu
            }
        }, false, true);

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(snapshot)));
    }

    private static string NormalizeSnapshotValue(string? value)
    {
        return value ?? string.Empty;
    }

    private static async Task<int> RefreshServerIPInfoAfterSubscriptionUpdate(Config config, bool blProxy)
    {
        var profileItems = await AppManager.Instance.ProfileItems(string.Empty);
        if (profileItems is not { Count: > 0 })
        {
            return 0;
        }

        var candidates = profileItems
            .Where(t => !t.ConfigType.IsComplexType() && t.IsValid() && t.Address.IsNotEmpty())
            .ToList();
        if (candidates.Count == 0)
        {
            return 0;
        }

        var ipInfoTasks = new ConcurrentDictionary<string, Task<string>>();
        using var semaphore = new SemaphoreSlim(Math.Max(1, config.SpeedTestItem.MixedConcurrencyCount));
        var refreshedCount = 0;

        var tasks = candidates.Select(async item =>
        {
            await semaphore.WaitAsync();
            try
            {
                var ipInfo = await ipInfoTasks.GetOrAdd(item.Address.TrimEx(), address => GetServerIPInfoString(address, blProxy));
                ProfileExManager.Instance.SetTestIpInfo(item.IndexId, ipInfo);
                Interlocked.Increment(ref refreshedCount);
            }
            finally
            {
                semaphore.Release();
            }
        });

        await Task.WhenAll(tasks);
        await ProfileExManager.Instance.SaveTo();
        return refreshedCount;
    }

    private static async Task<string> GetServerIPInfoString(string address, bool blProxy)
    {
        var ipInfo = await ConnectionHandler.GetIPInfoForAddress(address, blProxy);
        return ipInfo?.ToString() ?? Global.None;
    }

    private static bool IsValidSubscription(SubItem item, string subId)
    {
        var id = item.Id.TrimEx();
        var url = item.Url.TrimEx();

        if (id.IsNullOrEmpty() || url.IsNullOrEmpty())
        {
            return false;
        }

        if (subId.IsNotEmpty() && item.Id != subId)
        {
            return false;
        }

        if (!url.StartsWith(Global.HttpsProtocol) && !url.StartsWith(Global.HttpProtocol))
        {
            return false;
        }

        return true;
    }

    private static DownloadService CreateDownloadHandler(string hashCode, Func<bool, string, Task> updateFunc)
    {
        var downloadHandle = new DownloadService();
        downloadHandle.Error += (sender2, args) =>
        {
            updateFunc?.Invoke(false, $"{hashCode}{args.GetException().Message}");
        };
        return downloadHandle;
    }

    private static async Task<string> DownloadSubscriptionContent(DownloadService downloadHandle, string url, bool blProxy, string userAgent)
    {
        var result = await downloadHandle.TryDownloadString(url, blProxy, userAgent);

        // If download with proxy fails, try direct connection
        if (blProxy && result.IsNullOrEmpty())
        {
            result = await downloadHandle.TryDownloadString(url, false, userAgent);
        }

        return result ?? string.Empty;
    }

    private static async Task<string> DownloadAllSubscriptions(Config config, SubItem item, bool blProxy, DownloadService downloadHandle)
    {
        // Download main subscription content
        var result = await DownloadMainSubscription(config, item, blProxy, downloadHandle);

        // Process additional subscription links (if any)
        if (item.ConvertTarget.IsNullOrEmpty() && item.MoreUrl.TrimEx().IsNotEmpty())
        {
            result = await DownloadAdditionalSubscriptions(item, result, blProxy, downloadHandle);
        }

        return result;
    }

    private static async Task<string> DownloadMainSubscription(Config config, SubItem item, bool blProxy, DownloadService downloadHandle)
    {
        // Prepare subscription URL and download directly
        var url = Utils.GetPunycode(item.Url.TrimEx());

        // If conversion is needed
        if (item.ConvertTarget.IsNotEmpty())
        {
            var subConvertUrl = config.ConstItem.SubConvertUrl.IsNullOrEmpty()
                ? Global.SubConvertUrls.FirstOrDefault()
                : config.ConstItem.SubConvertUrl;

            url = string.Format(subConvertUrl!, Utils.UrlEncode(url));

            if (!url.Contains("target="))
            {
                url += $"&target={item.ConvertTarget}";
            }

            if (!url.Contains("config="))
            {
                url += $"&config={Global.SubConvertConfig.FirstOrDefault()}";
            }
        }

        // Download and return result directly
        return await DownloadSubscriptionContent(downloadHandle, url, blProxy, item.UserAgent);
    }

    private static async Task<string> DownloadAdditionalSubscriptions(SubItem item, string mainResult, bool blProxy, DownloadService downloadHandle)
    {
        var result = mainResult;

        // If main subscription result is Base64 encoded, decode it first
        if (result.IsNotEmpty() && Utils.IsBase64String(result))
        {
            result = Utils.Base64Decode(result);
        }

        // Process additional URL list
        var lstUrl = item.MoreUrl.TrimEx().Split(",") ?? [];
        foreach (var it in lstUrl)
        {
            var url2 = Utils.GetPunycode(it);
            if (url2.IsNullOrEmpty())
            {
                continue;
            }

            var additionalResult = await DownloadSubscriptionContent(downloadHandle, url2, blProxy, item.UserAgent);

            if (additionalResult.IsNotEmpty())
            {
                // Process additional subscription results, add to main result
                if (Utils.IsBase64String(additionalResult))
                {
                    result += Environment.NewLine + Utils.Base64Decode(additionalResult);
                }
                else
                {
                    result += Environment.NewLine + additionalResult;
                }
            }
        }

        return result;
    }

    private static async Task<int> ProcessDownloadResult(Config config, string id, string result, string hashCode, Func<bool, string, Task> updateFunc)
    {
        if (result.IsNullOrEmpty())
        {
            await updateFunc?.Invoke(false, $"{hashCode}{ResUI.MsgSubscriptionDecodingFailed}");
            return 0;
        }

        await updateFunc?.Invoke(false, $"{hashCode}{ResUI.MsgGetSubscriptionSuccessfully}");

        // If result is too short, display content directly
        if (result.Length < 99)
        {
            await updateFunc?.Invoke(false, $"{hashCode}{result}");
        }

        await updateFunc?.Invoke(false, $"{hashCode}{ResUI.MsgStartParsingSubscription}");

        // Add servers to configuration
        var ret = await ConfigHandler.AddBatchServers(config, result, id, true);
        if (ret <= 0)
        {
            Logging.SaveLog($"FailedImportSubscription, contentLength={result.Length}");
        }

        // Update completion message
        await updateFunc?.Invoke(false, ret > 0
                ? $"{hashCode}{ResUI.MsgUpdateSubscriptionEnd}"
                : $"{hashCode}{ResUI.MsgFailedImportSubscription}");

        return Math.Max(0, ret);
    }
}
