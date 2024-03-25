import logging
from bisect import bisect_right
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Set, Tuple

from wake.testing import *
from wake.testing.fuzzing import *

from pytypes.contracts.Voting import Voting
from pytypes.contracts.aragon.os.acl.ACL import ACL
from pytypes.contracts.aragon.os.evmscript.IEVMScriptExecutor import IEVMScriptExecutor
from pytypes.contracts.aragon.os.kernel.Kernel import Kernel
from pytypes.contracts.aragon.minime.MiniMeToken import MiniMeTokenFactory, MiniMeToken
from pytypes.contracts.aragon.os.evmscript.EVMScriptRegistry import EVMScriptRegistry
from pytypes.tests.Deployer import Deployer

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


mini_me_factory_code = bytes.fromhex((Path(__file__).parent.parent / "bin" / "MiniMeTokenFactory.bin").read_text())
acl_code = bytes.fromhex((Path(__file__).parent.parent / "bin" / "ACL.bin").read_text())
kernel_code = bytes.fromhex((Path(__file__).parent.parent / "bin" / "Kernel.bin").read_text())
script_registry_code = bytes.fromhex((Path(__file__).parent.parent / "bin" / "EVMScriptRegistry.bin").read_text())
script_executor_code = bytes.fromhex((Path(__file__).parent.parent / "bin" / "ScriptExecutor.bin").read_text())
voting_code = bytes.fromhex((Path(__file__).parent.parent / "bin" / "Voting.bin").read_text())


@dataclass
class Vote:
    vote_id: uint256
    start: int
    snapshot_block: int
    min_support: int
    min_accept: int
    voting_power: int
    script: bytes
    executed: bool
    yea_voters: Set[Account]
    nay_voters: Set[Account]


class TokenSnapshots:
    _total_supply_snapshots: List[Tuple[int, int]]
    _balances_snapshots: Dict[Account, List[Tuple[int, int]]]

    def __init__(self):
        self._total_supply_snapshots = []
        self._balances_snapshots = defaultdict(list)

    def total_supply(self) -> int:
        return self.total_supply_at(default_chain.blocks["latest"].number)

    def balance_of(self, account: Account) -> int:
        return self.balance_of_at(account, default_chain.blocks["latest"].number)

    def total_supply_at(self, block_number: int) -> int:
        index = bisect_right(self._total_supply_snapshots, block_number, key=lambda x: x[0])
        if index == 0:
            return 0
        return self._total_supply_snapshots[index - 1][1]

    def balance_of_at(self, account: Account, block_number: int) -> int:
        index = bisect_right(self._balances_snapshots[account], block_number, key=lambda x: x[0])
        if index == 0:
            return 0
        return self._balances_snapshots[account][index - 1][1]

    def generate_tokens(self, account: Account, amount: int) -> None:
        self._balances_snapshots[account].append((default_chain.blocks["latest"].number, self.balance_of(account) + amount))
        self._total_supply_snapshots.append((default_chain.blocks["latest"].number, self.total_supply() + amount))

    def destroy_tokens(self, account: Account, amount: int) -> None:
        self._balances_snapshots[account].append((default_chain.blocks["latest"].number, self.balance_of(account) - amount))
        self._total_supply_snapshots.append((default_chain.blocks["latest"].number, self.total_supply() - amount))


class VotingFuzzTest(FuzzTest):
    token: MiniMeToken
    kernel: Kernel
    script_executor: IEVMScriptExecutor
    voting: Voting
    voting_admin: Account

    delegates: Dict[Account, Set[Account]]
    votes: Dict[uint256, Vote]
    vote_time: int
    objection_time: int
    support_required_pct: int
    min_accept_quorum_pct: int

    no_power_accounts: Set[Account]
    self_votes: Dict[uint256, Set[Account]]
    snapshots: TokenSnapshots

    def pre_sequence(self) -> None:
        default_chain.default_tx_account = default_chain.accounts[0]

        self.no_power_accounts = set(random.sample(default_chain.accounts, 5))
        self.self_votes = defaultdict(set)
        self.delegates = defaultdict(set)
        self.votes = {}
        self.snapshots = TokenSnapshots()

        self.vote_time = random_int(60*60, 60*60*24*10)  # 1h - 10d
        self.objection_time = random_int(0, self.vote_time // 3)
        self.support_required_pct = random_int(10**17, 4 * 10**17)  # 10% - 40%
        self.min_accept_quorum_pct = random_int(10**17, self.support_required_pct)
        deployer = Deployer.deploy()

        token_factory = MiniMeTokenFactory(deployer.deploy_(mini_me_factory_code).return_value)
        self.token = token_factory.createCloneToken(MiniMeToken(Address(0)), 0, "Lido DAO Token", 18, "LDO", True).return_value

        acl_template = ACL(deployer.deploy_(acl_code).return_value)

        self.kernel = Kernel(deployer.deploy_(kernel_code + abi.encode_packed(False)).return_value)
        self.kernel.initialize(acl_template, default_chain.accounts[0])
        kernel_acl = ACL(self.kernel.acl())
        kernel_acl.createPermission(default_chain.accounts[0], self.kernel, self.kernel.APP_MANAGER_ROLE(), default_chain.accounts[0])

        registry_impl = EVMScriptRegistry(deployer.deploy_(script_registry_code).return_value)
        registry_app_id = bytes.fromhex("ddbcfd564f642ab5627cf68b9b7d374fb4f8a36e941a75d89c87998cef03bd61")
        registry = EVMScriptRegistry(self.kernel.newAppInstance_(
            registry_app_id,
            registry_impl,
            abi.encode_call(registry_impl.initialize, []),
            True,
        ).return_value)

        self.script_executor = IEVMScriptExecutor(deployer.deploy_(script_executor_code).return_value)

        kernel_acl.createPermission(default_chain.accounts[0], registry, registry.REGISTRY_ADD_EXECUTOR_ROLE(), default_chain.accounts[0])
        registry.addScriptExecutor(self.script_executor)
        # creates executor with id 1

        impl = Voting(deployer.deploy_(voting_code).return_value)

        app_id = random_bytes(32)
        self.voting = Voting(self.kernel.newAppInstance(app_id, impl).return_value)
        self.voting.initialize(self.token, self.support_required_pct, self.min_accept_quorum_pct, self.vote_time, self.objection_time)

        self.voting_admin = random_account()
        kernel_acl.createPermission(self.voting_admin, self.voting, self.voting.CREATE_VOTES_ROLE(), self.voting_admin)
        kernel_acl.createPermission(self.voting_admin, self.voting, self.voting.UNSAFELY_MODIFY_VOTE_TIME_ROLE(), self.voting_admin)
        kernel_acl.createPermission(self.voting_admin, self.voting, self.voting.MODIFY_SUPPORT_ROLE(), self.voting_admin)
        kernel_acl.createPermission(self.voting_admin, self.voting, self.voting.MODIFY_QUORUM_ROLE(), self.voting_admin)

        # distribute tokens
        for account in set(default_chain.accounts) - self.no_power_accounts:
            amount = random_int(10**18, 10**19)
            self.token.generateTokens(account, amount)
            self.snapshots.generate_tokens(account, amount)

        default_chain.default_tx_account = random_account()

    def post_invariants(self) -> None:
        opened_votes = [v for v in self.votes.values() if not v.executed and default_chain.blocks["latest"].timestamp < v.start + self.vote_time]

        # roll time forward
        if random.random() < 0.8 or len(opened_votes) == 0:
            time_diff = random_int(self.vote_time // 1000, self.vote_time // 200)
            default_chain.mine(lambda t: t + time_diff)
        else:
            nearest_vote = min(opened_votes, key=lambda v: v.start + self.vote_time)
            new_timestamp = nearest_vote.start + self.vote_time + random.choice([-1, 0, 1])

            if new_timestamp <= default_chain.blocks["latest"].timestamp:
                default_chain.mine(lambda t: t + random_int(1, 10))
            else:
                default_chain.mine(lambda t: new_timestamp)

    def _get_vote_phase(self, vote: Vote, timestamp: int) -> Voting.VotePhase:
        if timestamp >= vote.start + self.vote_time:
            return Voting.VotePhase.Closed
        elif timestamp < vote.start + self.vote_time - self.objection_time:
            return Voting.VotePhase.Main
        else:
            return Voting.VotePhase.Objection

    def _can_execute_vote(self, vote: Vote) -> bool:
        yea = sum(self.snapshots.balance_of_at(v, vote.snapshot_block) for v in vote.yea_voters)
        nay = sum(self.snapshots.balance_of_at(v, vote.snapshot_block) for v in vote.nay_voters)

        return (
            not vote.executed and
            self._get_vote_phase(vote, default_chain.blocks["latest"].timestamp) == Voting.VotePhase.Closed and
            yea * 10 ** 18 > (yea + nay) * vote.min_support and
            yea * 10 ** 18 > vote.voting_power * vote.min_accept
        )

    @flow(weight=30)
    def flow_change_vote_time(self):
        new_vote_time = random_int(60*60, 60*60*24*10)  # 1h - 10d

        with may_revert("VOTING_VOTE_TIME_TOO_SMALL") as e:
            tx = self.voting.unsafelyChangeVoteTime(new_vote_time, from_=self.voting_admin)
            self.vote_time = new_vote_time

            assert tx.events == [Voting.ChangeVoteTime(new_vote_time)]

        assert (e.value is None) == (new_vote_time > self.objection_time)

    @flow(weight=30)
    def flow_change_objection_time(self):
        new_objection_time = random_int(0, self.vote_time // 3)

        with may_revert("VOTING_OBJECTION_TIME_TOO_BIG") as e:
            tx = self.voting.unsafelyChangeObjectionPhaseTime(new_objection_time, from_=self.voting_admin)
            self.objection_time = new_objection_time

            assert tx.events == [Voting.ChangeObjectionPhaseTime(new_objection_time)]

        assert (e.value is None) == (self.vote_time > new_objection_time)

    @flow(weight=30)
    def flow_change_support_required(self):
        new_support_required_pct = random_int(10**17, 4 * 10**17)  # 10% - 40%

        with may_revert("VOTING_CHANGE_SUPPORT_PCTS") as e:
            tx = self.voting.changeSupportRequiredPct(new_support_required_pct, from_=self.voting_admin)
            self.support_required_pct = new_support_required_pct

            assert tx.events == [Voting.ChangeSupportRequired(new_support_required_pct)]

        assert (e.value is None) == (new_support_required_pct >= self.min_accept_quorum_pct)

    @flow(weight=30)
    def flow_change_min_accept_quorum(self):
        new_min_accept_quorum_pct = random_int(10**17, 4 * 10**17)

        with may_revert("VOTING_CHANGE_QUORUM_PCTS") as e:
            tx = self.voting.changeMinAcceptQuorumPct(new_min_accept_quorum_pct, from_=self.voting_admin)
            self.min_accept_quorum_pct = new_min_accept_quorum_pct  # 10% - 40%

            assert tx.events == [Voting.ChangeMinQuorum(new_min_accept_quorum_pct)]

        assert (e.value is None) == (self.support_required_pct >= new_min_accept_quorum_pct)

    @flow()
    def flow_generate_tokens(self):
        owner = random_account(predicate=lambda a: a not in self.no_power_accounts)
        amount = random_int(10**18, 10**19)
        self.token.generateTokens(owner, amount, from_=default_chain.accounts[0])

        self.snapshots.generate_tokens(owner, amount)

        logger.info(f"Generated {amount} new tokens for {owner}")

    @flow()
    def flow_destroy_tokens(self):
        owner = random_account()
        amount = random_int(0, self.snapshots.balance_of(owner))
        self.token.destroyTokens(owner, amount, from_=default_chain.accounts[0])

        self.snapshots.destroy_tokens(owner, amount)

        logger.info(f"Destroyed {amount} tokens from {owner}")

    @flow()
    def flow_transfer_tokens(self):
        sender = random_account()
        receiver = random_account(predicate=lambda a: a not in self.no_power_accounts and a != sender)
        amount = random_int(0, self.snapshots.balance_of(sender))
        self.token.transfer(receiver, amount, from_=sender)

        self.snapshots.destroy_tokens(sender, amount)
        self.snapshots.generate_tokens(receiver, amount)

        logger.info(f"Transferred {amount} tokens from {sender} to {receiver}")

    @flow(weight=1000)
    def flow_new_vote(self):
        script = b"\x00\x00\x00\x01" + random_bytes(0, 100)
        metadata = random_string(0, 10)
        tx = self.voting.newVote(script, metadata, from_=self.voting_admin)
        vote_id = tx.return_value

        self.votes[vote_id] = Vote(
            vote_id,
            tx.block.timestamp,
            tx.block.number - 1,
            self.support_required_pct,
            self.min_accept_quorum_pct,
            self.snapshots.total_supply_at(tx.block.number),
            script,
            False,
            set(),
            set(),
        )

        assert tx.events == [Voting.StartVote(vote_id, self.voting_admin.address, metadata)]

        logger.info(f"New vote created: {self.votes[vote_id]}")

    @flow(weight=1000)
    def flow_vote(self):
        pending_timestamp = default_chain.blocks["pending"].timestamp
        main_vote_ids = [
            vote_id for vote_id, vote in self.votes.items()
            if self._get_vote_phase(vote, pending_timestamp) == Voting.VotePhase.Main
        ]

        if len(self.votes) == 0:
            vote_id = random_int(0, 2**256 - 1)
        elif random.random() < 0.2 or len(main_vote_ids) == 0:
            vote_id = random.choice(list(self.votes.keys()))
            vote = self.votes[vote_id]
            expected_phase = self._get_vote_phase(vote, pending_timestamp)
        else:
            vote_id = random.choice(main_vote_ids)
            vote = self.votes[vote_id]
            expected_phase = Voting.VotePhase.Main
        supports = random_bool(true_prob=0.7)
        voter = random_account()

        with may_revert(("VOTING_NO_VOTE", "VOTING_CAN_NOT_VOTE", "VOTING_NO_VOTING_POWER")) as e:
            tx = self.voting.vote(vote_id, supports, random_bool(), from_=voter)

            if supports:
                self.votes[vote_id].yea_voters.add(voter)
                self.votes[vote_id].nay_voters.discard(voter)
            else:
                self.votes[vote_id].nay_voters.add(voter)
                self.votes[vote_id].yea_voters.discard(voter)
            self.self_votes[vote_id].add(voter)

        if vote_id not in self.votes:
            assert e.value == Error("VOTING_NO_VOTE")
        elif expected_phase == Voting.VotePhase.Objection and supports or expected_phase == Voting.VotePhase.Closed or vote.executed:
            assert e.value == Error("VOTING_CAN_NOT_VOTE")
        elif self.snapshots.balance_of(voter) == 0:
            assert e.value == Error("VOTING_NO_VOTING_POWER")
        else:
            assert e.value is None

            events: List = [Voting.CastVote(vote_id, voter.address, supports, self.snapshots.balance_of_at(voter, vote.snapshot_block))]
            if expected_phase == Voting.VotePhase.Objection:
                events.append(Voting.CastObjection(vote_id, voter.address, self.snapshots.balance_of_at(voter, vote.snapshot_block)))

            assert tx.events == events

            logger.info(f"{voter} voted {'for' if supports else 'against'} vote {self.votes[vote_id]} with {self.snapshots.balance_of_at(voter, tx.block_number)} tokens")

    @flow(weight=1000)
    def flow_vote_for(self):
        pending_timestamp = default_chain.blocks["pending"].timestamp
        main_vote_ids = [
            vote_id for vote_id, vote in self.votes.items()
            if self._get_vote_phase(vote, pending_timestamp) == Voting.VotePhase.Main
        ]

        if len(self.votes) == 0:
            vote_id = random_int(0, 2**256 - 1)
        elif random.random() < 0.2 or len(main_vote_ids) == 0:
            vote_id = random.choice(list(self.votes.keys()))
            vote = self.votes[vote_id]
            expected_phase = self._get_vote_phase(vote, pending_timestamp)
        else:
            vote_id = random.choice(main_vote_ids)
            vote = self.votes[vote_id]
            expected_phase = Voting.VotePhase.Main

        supports = random_bool()
        delegate = random_account()
        if len(self.delegates[delegate]) == 0:
            voter = random_account()
        else:
            voter = random.choice(list(self.delegates[delegate]))

        with may_revert(("VOTING_NO_VOTE", "VOTING_CAN_NOT_VOTE", "VOTING_NO_VOTING_POWER", "VOTING_CAN_NOT_VOTE_FOR")) as e:
            tx = self.voting.attemptVoteFor(vote_id, supports, voter, from_=delegate)

            if supports:
                self.votes[vote_id].yea_voters.add(voter)
                self.votes[vote_id].nay_voters.discard(voter)
            else:
                self.votes[vote_id].nay_voters.add(voter)
                self.votes[vote_id].yea_voters.discard(voter)

        if vote_id not in self.votes:
            assert e.value == Error("VOTING_NO_VOTE")
        elif expected_phase == Voting.VotePhase.Objection and supports or expected_phase == Voting.VotePhase.Closed or vote.executed:
            assert e.value == Error("VOTING_CAN_NOT_VOTE")
        elif self.snapshots.balance_of(voter) == 0:
            assert e.value == Error("VOTING_NO_VOTING_POWER")
        elif voter not in self.delegates[delegate] or voter in self.self_votes[vote_id]:
            assert e.value == Error("VOTING_CAN_NOT_VOTE_FOR")
        else:
            assert e.value is None

            events: List = [Voting.CastVote(vote_id, voter.address, supports, self.snapshots.balance_of_at(voter, vote.snapshot_block))]
            if expected_phase == Voting.VotePhase.Objection:
                events.append(Voting.CastObjection(vote_id, voter.address, self.snapshots.balance_of_at(voter, vote.snapshot_block)))
            events.append(Voting.CastVoteAsDelegate(vote_id, delegate.address, voter.address, supports, self.snapshots.balance_of_at(voter, vote.snapshot_block)))

            assert tx.events == events

            logger.info(f"{delegate} voted on behalf of {voter} {'for' if supports else 'against'} vote {self.votes[vote_id]} with {self.snapshots.balance_of_at(voter, tx.block_number)} tokens")

    @flow(weight=1000)
    def flow_vote_for_multiple(self):
        pending_timestamp = default_chain.blocks["pending"].timestamp
        main_vote_ids = [
            vote_id for vote_id, vote in self.votes.items()
            if self._get_vote_phase(vote, pending_timestamp) == Voting.VotePhase.Main
        ]

        if len(self.votes) == 0:
            vote_id = random_int(0, 2**256 - 1)
        elif random.random() < 0.2 or len(main_vote_ids) == 0:
            vote_id = random.choice(list(self.votes.keys()))
            vote = self.votes[vote_id]
            expected_phase = self._get_vote_phase(vote, pending_timestamp)
        else:
            vote_id = random.choice(main_vote_ids)
            vote = self.votes[vote_id]
            expected_phase = Voting.VotePhase.Main

        supports = random_bool()
        delegate = random_account()
        voters = random.choices(list(self.delegates[delegate]), k=random_int(0, len(self.delegates[delegate])))  # intentionally voters may repeat

        with may_revert(("VOTING_NO_VOTE", "VOTING_CAN_NOT_VOTE", "VOTING_NO_VOTING_POWER", "VOTING_CAN_NOT_VOTE_FOR")) as e:
            tx = self.voting.attemptVoteForMultiple(vote_id, supports, list(voters), from_=delegate)

        if vote_id not in self.votes:
            assert e.value == Error("VOTING_NO_VOTE")
        elif expected_phase == Voting.VotePhase.Objection and supports or expected_phase == Voting.VotePhase.Closed or vote.executed:
            assert e.value == Error("VOTING_CAN_NOT_VOTE")
        else:
            events = []
            managed_to_vote = False
            for voter in voters:
                if self.snapshots.balance_of(voter) == 0:
                    assert e.value == Error("VOTING_NO_VOTING_POWER")
                    return
                if voter not in self.delegates[delegate] or voter in self.self_votes[vote_id]:
                    pass
                else:
                    managed_to_vote = True
                    if supports:
                        self.votes[vote_id].yea_voters.add(voter)
                        self.votes[vote_id].nay_voters.discard(voter)
                    else:
                        self.votes[vote_id].nay_voters.add(voter)
                        self.votes[vote_id].yea_voters.discard(voter)

                    events.append(Voting.CastVote(vote_id, voter.address, supports, self.snapshots.balance_of_at(voter, vote.snapshot_block)))
                    if expected_phase == Voting.VotePhase.Objection:
                        events.append(Voting.CastObjection(vote_id, voter.address, self.snapshots.balance_of_at(voter, vote.snapshot_block)))
                    events.append(Voting.CastVoteAsDelegate(vote_id, delegate.address, voter.address, supports, self.snapshots.balance_of_at(voter, vote.snapshot_block)))

            if not managed_to_vote:
                assert e.value == Error("VOTING_CAN_NOT_VOTE_FOR")
                return

            assert e.value is None
            assert tx.events == events

            logger.info(f"{delegate} voted on behalf of {list(self.delegates[delegate])} {'for' if supports else 'against'} vote {self.votes[vote_id]} with {sum(self.snapshots.balance_of_at(v, tx.block_number) for v in self.delegates[delegate])} tokens")

    @flow()
    def flow_execute(self):
        can_execute_votes = [v for v in self.votes.values() if self._can_execute_vote(v)]

        if len(self.votes) == 0:
            vote_id = random_int(0, 2**256 - 1)
            yea = nay = min_support_votes = min_accept_votes = 0
        elif random.random() < 0.2 or len(can_execute_votes) == 0:
            vote_id = random.choice(list(self.votes.keys()))
            vote = self.votes[vote_id]

            yea = sum(self.snapshots.balance_of_at(v, vote.snapshot_block) for v in vote.yea_voters)
            nay = sum(self.snapshots.balance_of_at(v, vote.snapshot_block) for v in vote.nay_voters)
            min_support_votes = (yea + nay) * vote.min_support
            min_accept_votes = vote.voting_power * vote.min_accept
        else:
            vote = random.choice(can_execute_votes)
            vote_id = vote.vote_id

            yea = sum(self.snapshots.balance_of_at(v, vote.snapshot_block) for v in vote.yea_voters)
            nay = sum(self.snapshots.balance_of_at(v, vote.snapshot_block) for v in vote.nay_voters)
            min_support_votes = (yea + nay) * vote.min_support
            min_accept_votes = vote.voting_power * vote.min_accept

        execute_timestamp = default_chain.blocks["pending"].timestamp

        with may_revert(("VOTING_NO_VOTE", "VOTING_CAN_NOT_EXECUTE")) as e:
            tx = self.voting.executeVote(vote_id, from_=random_account())

        if vote_id not in self.votes:
            assert e.value == Error("VOTING_NO_VOTE")
        elif (
            vote.executed or
            self._get_vote_phase(vote, execute_timestamp) != Voting.VotePhase.Closed or
            yea * 10 ** 18 <= min_support_votes or
            yea * 10 ** 18 <= min_accept_votes
        ):
            assert e.value == Error("VOTING_CAN_NOT_EXECUTE")
        else:
            assert e.value is None
            assert Voting.ExecuteVote(vote_id) in tx.events

            vote.executed = True

            logger.info(f"Executed vote {vote}")

    @flow()
    def flow_set_delegate(self):
        voter = random_account()
        delegate = random_account()

        current_delegate = next((d for d, v in self.delegates.items() if voter in v), None)

        with may_revert(("VOTING_SELF_DELEGATE", "VOTING_DELEGATE_SAME_AS_PREV", "VOTING_NO_VOTING_POWER")) as e:
            tx = self.voting.setDelegate(delegate, from_=voter)

        if voter == delegate:
            assert e.value == Error("VOTING_SELF_DELEGATE")
        elif current_delegate == delegate:
            assert e.value == Error("VOTING_DELEGATE_SAME_AS_PREV")
        elif self.snapshots.balance_of(voter) == 0:
            assert e.value == Error("VOTING_NO_VOTING_POWER")
        else:
            assert e.value is None
            events = []

            if current_delegate is not None:
                events.append(Voting.ResetDelegate(voter.address, current_delegate.address))
                self.delegates[current_delegate].remove(voter)
            self.delegates[delegate].add(voter)

            events.append(Voting.SetDelegate(voter.address, delegate.address))

            assert tx.events == events

        logger.info(f"{voter} delegated to {delegate}")

    @flow()
    def flow_reset_delegate(self):
        voter = random_account()

        with may_revert("VOTING_DELEGATE_NOT_SET") as e:
            tx = self.voting.resetDelegate(from_=voter)

        if not any(voter in delegates for delegates in self.delegates.values()):
            assert e.value == Error("VOTING_DELEGATE_NOT_SET")
        else:
            assert e.value is None

            delegate = next(d for d, v in self.delegates.items() if voter in v)
            assert tx.events == [Voting.ResetDelegate(voter.address, delegate.address)]

            self.delegates[delegate].remove(voter)

        logger.info(f"{voter} reset delegate")

    @invariant(period=15)
    def invariant_votes(self):
        # check only last 20 votes to avoid performance issues
        for vote in list(self.votes.values())[:-20]:
            latest_timestamp = default_chain.blocks["latest"].timestamp
            is_open = latest_timestamp - vote.start < self.vote_time and not vote.executed
            phase = self._get_vote_phase(vote, latest_timestamp)

            assert self.voting.getVotePhase(vote.vote_id) == phase

            yea = sum(self.snapshots.balance_of_at(v, vote.snapshot_block) for v in vote.yea_voters)
            nay = sum(self.snapshots.balance_of_at(v, vote.snapshot_block) for v in vote.nay_voters)

            assert self.voting.getVote(vote.vote_id) == (
                is_open, vote.executed, vote.start, vote.snapshot_block, vote.min_support, vote.min_accept,
                yea, nay, vote.voting_power, vote.script, phase,
            )

            assert self.voting.canExecute(vote.vote_id) == self._can_execute_vote(vote)

            states = []
            for acc in default_chain.accounts:
                if acc not in vote.yea_voters and acc not in vote.nay_voters:
                    state = Voting.VoterState.Absent
                elif acc in vote.yea_voters and acc in self.self_votes[vote.vote_id]:
                    state = Voting.VoterState.Yea
                elif acc in vote.nay_voters and acc in self.self_votes[vote.vote_id]:
                    state = Voting.VoterState.Nay
                elif acc in vote.yea_voters:
                    state = Voting.VoterState.DelegateYea
                elif acc in vote.nay_voters:
                    state = Voting.VoterState.DelegateNay
                else:
                    raise AssertionError
                states.append(state)

                assert self.voting.getVoterState(vote.vote_id, acc) == state
                assert self.voting.canVote(vote.vote_id, acc) == (is_open and self.snapshots.balance_of_at(acc, vote.snapshot_block) > 0)

                delegated_voters, voting_power = self.voting.getDelegatedVotersAtVote(acc, 0, 100, vote.vote_id)
                assert {Account(v) for v in delegated_voters} == self.delegates[acc]
                assert voting_power == [self.snapshots.balance_of_at(Account(v), vote.snapshot_block) for v in delegated_voters]

            assert self.voting.getVotersStateAtVote(vote.vote_id, list(default_chain.accounts)) == states

    @invariant(period=15)
    def invariant_delegated_voters(self):
        for acc in default_chain.accounts:
            voters, powers = self.voting.getDelegatedVoters(acc, 0, 100)
            assert {Account(v) for v in voters} == self.delegates[acc]
            assert powers == [self.snapshots.balance_of(Account(v)) for v in voters]

            assert self.voting.getDelegate(acc) == next((d.address for d, a in self.delegates.items() if acc in a), Address(0))
            assert self.voting.getDelegatedVotersCount(acc) == len(self.delegates[acc])


@default_chain.connect(accounts=20)
@on_revert(lambda e: print(e.tx.call_trace if e.tx is not None else 'Call reverted'))
def test_voting():
    VotingFuzzTest().run(10, 10_000)
