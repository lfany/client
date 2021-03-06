package teams

import (
	"encoding/json"
	"fmt"

	"golang.org/x/net/context"

	"github.com/keybase/client/go/libkb"
	"github.com/keybase/client/go/protocol/keybase1"
)

func getInternalByStringName(ctx context.Context, g *libkb.GlobalContext, name string) (*Team, error) {
	f := newFinder(g)
	return f.findByStringName(ctx, name)
}

func getInternal(ctx context.Context, g *libkb.GlobalContext, id keybase1.TeamID) (*Team, error) {
	f := newFinder(g)
	return f.findByID(ctx, id)
}

type finder struct {
	libkb.Contextified
}

func newFinder(g *libkb.GlobalContext) *finder {
	return &finder{
		Contextified: libkb.NewContextified(g),
	}
}

func (f *finder) findByID(ctx context.Context, id keybase1.TeamID) (*Team, error) {
	raw, err := f.rawTeamByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return f.playRaw(ctx, raw)
}

func (f *finder) findByStringName(ctx context.Context, name string) (*Team, error) {
	raw, err := f.rawTeam(ctx, name)
	if err != nil {
		return nil, err
	}

	return f.playRaw(ctx, raw)
}

func (f *finder) playRaw(ctx context.Context, raw *rawTeam) (*Team, error) {
	team := NewTeam(f.G(), raw.Name.String())
	team.ID = raw.ID
	if raw.Box == nil {
		return nil, fmt.Errorf("missing team box")
	}
	team.Box = *raw.Box
	team.ReaderKeyMasks = raw.ReaderKeyMasks
	team.Prevs = raw.Prevs

	links, err := raw.parseLinks(ctx)
	if err != nil {
		return nil, err
	}

	player, err := f.newPlayer(ctx, links)
	if err != nil {
		return nil, err
	}

	state, err := player.GetState()
	if err != nil {
		return nil, err
	}

	team.Chain = &state

	return team, nil
}

func (f *finder) rawTeam(ctx context.Context, name string) (*rawTeam, error) {
	arg := f.getArg(ctx)
	arg.Args = libkb.HTTPArgs{
		"name": libkb.S{Val: name},
	}
	return f.getDecode(arg)
}

func (f *finder) rawTeamByID(ctx context.Context, id keybase1.TeamID) (*rawTeam, error) {
	arg := f.getArg(ctx)
	arg.Args = libkb.HTTPArgs{
		"id": libkb.S{Val: id.String()},
	}
	return f.getDecode(arg)
}

func (f *finder) getArg(ctx context.Context) libkb.APIArg {
	arg := libkb.NewRetryAPIArg("team/get")
	arg.NetContext = ctx
	arg.SessionType = libkb.APISessionTypeREQUIRED
	return arg
}

func (f *finder) getDecode(arg libkb.APIArg) (*rawTeam, error) {
	var rt rawTeam
	if err := f.G().API.GetDecode(arg, &rt); err != nil {
		return nil, err
	}
	return &rt, nil
}

func (f *finder) newPlayer(ctx context.Context, links []SCChainLink) (*TeamSigChainPlayer, error) {
	uv, err := loadUserVersionByUID(ctx, f.G(), f.G().Env.GetUID())
	if err != nil {
		return nil, err
	}
	player := NewTeamSigChainPlayer(f.G(), uv)
	if err := player.AddChainLinks(ctx, links); err != nil {
		return nil, err
	}
	return player, nil
}

type rawTeam struct {
	ID             keybase1.TeamID                                        `json:"id"`
	Name           keybase1.TeamName                                      `json:"name"`
	Status         libkb.AppStatus                                        `json:"status"`
	Chain          []json.RawMessage                                      `json:"chain"`
	Box            *TeamBox                                               `json:"box"`
	Prevs          map[keybase1.PerTeamKeyGeneration]prevKeySealedEncoded `json:"prevs"`
	ReaderKeyMasks []keybase1.ReaderKeyMask                               `json:"reader_key_masks"`
}

func (r *rawTeam) GetAppStatus() *libkb.AppStatus {
	return &r.Status
}

func (r *rawTeam) parseLinks(ctx context.Context) ([]SCChainLink, error) {
	var links []SCChainLink
	for _, raw := range r.Chain {
		link, err := ParseTeamChainLink(string(raw))
		if err != nil {
			return nil, err
		}
		links = append(links, link)
	}
	return links, nil
}

func GetForTeamManagementByStringName(ctx context.Context, g *libkb.GlobalContext, name string) (*Team, error) {
	return getInternalByStringName(ctx, g, name)
}

func GetForTeamManagement(ctx context.Context, g *libkb.GlobalContext, id keybase1.TeamID) (*Team, error) {
	return getInternal(ctx, g, id)
}

func GetForApplication(ctx context.Context, g *libkb.GlobalContext, id keybase1.TeamID, app keybase1.TeamApplication, refreshers keybase1.TeamRefreshers) (*Team, error) {
	// TODO -- use the `application` and `refreshers` arguments
	return getInternal(ctx, g, id)
}

func GetForApplicationByStringName(ctx context.Context, g *libkb.GlobalContext, name string, app keybase1.TeamApplication, refreshers keybase1.TeamRefreshers) (*Team, error) {
	teamName, err := keybase1.TeamNameFromString(name)
	if err != nil {
		return nil, err
	}
	return GetForApplicationByName(ctx, g, teamName, app, refreshers)
}

func GetForApplicationByName(ctx context.Context, g *libkb.GlobalContext, name keybase1.TeamName, app keybase1.TeamApplication, refreshers keybase1.TeamRefreshers) (*Team, error) {
	id, err := ResolveNameToID(ctx, g, name)
	if err != nil {
		return nil, err
	}
	return GetForApplication(ctx, g, id, app, refreshers)
}

func GetForChatByStringName(ctx context.Context, g *libkb.GlobalContext, s string, refreshers keybase1.TeamRefreshers) (*Team, error) {
	return GetForApplicationByStringName(ctx, g, s, keybase1.TeamApplication_CHAT, refreshers)
}
