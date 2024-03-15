namespace AspNet.Security.OpenId.Steam;

/// <summary>
/// Claims from the user information endpoint: https://developer.valvesoftware.com/wiki/Steam_Web_API#GetPlayerSummaries_.28v0002.29
/// </summary>
public static class SteamClaimTypes
{
    // Public
    public const string SteamId = "steamid";
    public const string DisplayName = "personaname";
    public const string ProfileUrl = "profileurl";
    public const string Avatar = "avatar";
    public const string AvatarMedium = "avatarmedium";
    public const string AvatarFull = "avatarfull";
    /// <summary>
    /// The user's current status. 0 - Offline, 1 - Online, 2 - Busy, 3 - Away, 4 - Snooze, 5 - looking to trade, 6 - looking to play. If the player's profile is private, this will always be "0", except is the user has set their status to looking to trade or looking to play, because a bug makes those status appear even if the profile is private.
    /// </summary>
    public const string PersonaState = "personastate";
    /// <summary>
    /// There are only two possible values returned: 1 - the profile is not visible to you (Private, Friends Only, etc), 3 - the profile is "Public", and the data is visible.
    /// </summary>
    public const string CommunityVisibilityState = "communityvisibilitystate";
    /// <summary>
    /// If set, indicates the user has a community profile configured (will be set to '1')
    /// </summary>
    public const string ProfileState = "profilestate";
    public const string LastLogOff = "lastlogoff";
    public const string CommentPermission = "commentpermission";

    // Private
    public const string RealName = "realname";
    public const string PrimaryGroup = "primaryclanid";
    public const string TimeCreated = "timecreated";
    public const string CurrentGameId = "gameid";
    public const string CurrentGameServerIp = "gameserverip";
    public const string CurrentGameExtraInfo = "gameextrainfo";
    public const string CountryCode = "loccountrycode";
    public const string StateCode = "locstatecode";
    public const string CityId = "loccityid";
}
