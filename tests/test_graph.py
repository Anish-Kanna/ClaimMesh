import pytest
from uuid import uuid4

from app.graph import DependencyGraph, CycleError


def test_simple_chain():
    """A -> B -> C"""
    graph = DependencyGraph()
    a, b, c = uuid4(), uuid4(), uuid4()

    graph.add_dependency(a, b)
    graph.add_dependency(b, c)

    # Closure of A should include A, B, C
    closure_a = graph.closure(a)
    assert closure_a == {a, b, c}

    # Closure of B should include B, C
    closure_b = graph.closure(b)
    assert closure_b == {b, c}

    # Closure of C should include only C
    closure_c = graph.closure(c)
    assert closure_c == {c}


def test_diamond_shared_dependency():
    """A depends on B and C; both B and C depend on D (shared)."""
    graph = DependencyGraph()
    a, b, c, d = uuid4(), uuid4(), uuid4(), uuid4()

    graph.add_dependency(a, b)
    graph.add_dependency(a, c)
    graph.add_dependency(b, d)
    graph.add_dependency(c, d)

    # Closure of A should include all four nodes, D only once
    closure_a = graph.closure(a)
    assert closure_a == {a, b, c, d}

    # Closure of B and C both include D
    assert graph.closure(b) == {b, d}
    assert graph.closure(c) == {c, d}


def test_isolated_node():
    """Node with no dependencies."""
    graph = DependencyGraph()
    x = uuid4()
    graph.add_artifact(x)

    closure_x = graph.closure(x)
    assert closure_x == {x}


def test_unknown_node_raises():
    """Closure of unknown node should raise KeyError."""
    graph = DependencyGraph()
    known = uuid4()
    graph.add_artifact(known)

    unknown = uuid4()
    with pytest.raises(KeyError):
        graph.closure(unknown)


def test_cycle_insertion_rejected():
    """Adding an edge that creates a cycle should raise CycleError."""
    graph = DependencyGraph()
    a, b, c = uuid4(), uuid4(), uuid4()

    graph.add_dependency(a, b)
    graph.add_dependency(b, c)

    # Adding c -> a would create a cycle a->b->c->a
    with pytest.raises(CycleError) as exc:
        graph.add_dependency(c, a)

    # The cycle should contain the three nodes
    cycle = exc.value.cycle
    assert set(cycle) == {a, b, c}


def test_self_loop_rejected():
    """Adding a self-loop should raise CycleError."""
    graph = DependencyGraph()
    a = uuid4()
    graph.add_artifact(a)

    with pytest.raises(CycleError):
        graph.add_dependency(a, a)


def test_cycle_detection_on_existing_graph():
    """has_cycle() should detect cycles in the graph."""
    graph = DependencyGraph()
    a, b = uuid4(), uuid4()

    graph.add_dependency(a, b)
    assert not graph.has_cycle()

    # Manually add a cycle (bypassing add_dependency to test has_cycle)
    graph._graph.add_edge(b, a)
    assert graph.has_cycle()


def test_deterministic_closure_order():
    """Closure should be deterministic regardless of insertion order."""
    # Build same graph with different insertion orders
    def build_graph(order: list[tuple]):
        g = DependencyGraph()
        for parent, child in order:
            g.add_dependency(parent, child)
        return g

    a, b, c, d = uuid4(), uuid4(), uuid4(), uuid4()

    order1 = [(a, b), (a, c), (b, d), (c, d)]
    order2 = [(c, d), (b, d), (a, c), (a, b)]
    order3 = [(a, c), (b, d), (a, b), (c, d)]

    g1 = build_graph(order1)
    g2 = build_graph(order2)
    g3 = build_graph(order3)

    # All closures should be equal sets
    assert g1.closure(a) == g2.closure(a) == g3.closure(a) == {a, b, c, d}

    # Nodes and edges should be deterministically ordered
    assert g1.nodes() == g2.nodes() == g3.nodes()
    assert g1.edges() == g2.edges() == g3.edges()


def test_direct_dependencies_and_reverse_dependents():
    """Test direct_dependencies and reverse_dependents methods."""
    graph = DependencyGraph()
    a, b, c = uuid4(), uuid4(), uuid4()

    graph.add_dependency(a, b)
    graph.add_dependency(a, c)

    # Direct dependencies of A are B and C
    assert graph.direct_dependencies(a) == {b, c}

    # Reverse dependents of B is A
    assert graph.reverse_dependents(b) == {a}
    assert graph.reverse_dependents(c) == {a}

    # B and C have no dependencies
    assert graph.direct_dependencies(b) == set()
    assert graph.direct_dependencies(c) == set()


def test_add_artifact_idempotent():
    """Adding the same artifact multiple times should be idempotent."""
    graph = DependencyGraph()
    a = uuid4()

    graph.add_artifact(a)
    graph.add_artifact(a)  # second time

    assert len(graph) == 1
    assert a in graph