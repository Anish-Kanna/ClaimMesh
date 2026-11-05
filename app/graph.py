from __future__ import annotations

from typing import Set, List, Optional
from uuid import UUID

import networkx as nx


class CycleError(Exception):
    """Raised when adding a dependency would create a cycle."""
    def __init__(self, cycle: List[UUID]):
        self.cycle = cycle
        super().__init__(f"Cycle detected: {cycle}")


class DependencyGraph:
    """
    Wrapper around networkx.DiGraph representing artifact dependencies.
    Edge direction: parent -> dependency (i.e., parent depends on child).
    """

    def __init__(self):
        self._graph = nx.DiGraph()

    def add_artifact(self, artifact_id: UUID) -> None:
        """Add a node (artifact) to the graph if not already present."""
        if not self._graph.has_node(artifact_id):
            self._graph.add_node(artifact_id)

    def add_dependency(self, parent: UUID, child: UUID) -> None:
        """
        Add a directed edge parent -> child (parent depends on child).
        Raises CycleError if the edge would introduce a cycle.
        """
        # Ensure both nodes exist
        self.add_artifact(parent)
        self.add_artifact(child)

        # Check for cycle before adding
        if self._would_create_cycle(parent, child):
            # Find the cycle for reporting
            cycle = self._find_cycle(parent, child)
            raise CycleError(cycle)

        self._graph.add_edge(parent, child)

    def _would_create_cycle(self, parent: UUID, child: UUID) -> bool:
        """Return True if adding parent->child would create a cycle."""
        # If there's already a path from child to parent, adding parent->child closes a cycle
        return nx.has_path(self._graph, child, parent)

    def _find_cycle(self, parent: UUID, child: UUID) -> List[UUID]:
        """Return a cycle path if one exists after adding parent->child."""
        # Temporarily add the edge to find the cycle
        self._graph.add_edge(parent, child)
        try:
            cycle = nx.find_cycle(self._graph, orientation="original")
            # Convert edge list to node list
            nodes = [edge[0] for edge in cycle]
            # Close the cycle
            if cycle:
                nodes.append(cycle[0][0])
            return nodes
        except nx.NetworkXNoCycle:
            return []
        finally:
            # Remove the temporary edge
            self._graph.remove_edge(parent, child)

    def has_cycle(self) -> bool:
        """Return True if the graph contains any cycle."""
        try:
            nx.find_cycle(self._graph, orientation="original")
            return True
        except nx.NetworkXNoCycle:
            return False

    def closure(self, node: UUID) -> Set[UUID]:
        """
        Return the transitive closure of `node`, including the node itself.
        Closure = {node} ∪ all nodes reachable from node via outgoing edges.
        """
        if not self._graph.has_node(node):
            raise KeyError(f"Node {node} not found in graph")
        # networkx.descendants returns all nodes reachable from node (excluding node)
        descendants = nx.descendants(self._graph, node)
        return {node} | descendants

    def direct_dependencies(self, node: UUID) -> Set[UUID]:
        """Return immediate dependencies (outgoing edges) of node."""
        if not self._graph.has_node(node):
            raise KeyError(f"Node {node} not found in graph")
        return set(self._graph.successors(node))

    def reverse_dependents(self, node: UUID) -> Set[UUID]:
        """Return immediate dependents (incoming edges) of node."""
        if not self._graph.has_node(node):
            raise KeyError(f"Node {node} not found in graph")
        return set(self._graph.predecessors(node))

    def nodes(self) -> List[UUID]:
        """Return a deterministic (sorted) list of all nodes."""
        return sorted(self._graph.nodes(), key=str)

    def edges(self) -> List[tuple[UUID, UUID]]:
        """Return a deterministic (sorted) list of all edges."""
        return sorted(self._graph.edges(), key=lambda e: (str(e[0]), str(e[1])))

    def __contains__(self, node: UUID) -> bool:
        return self._graph.has_node(node)

    def __len__(self) -> int:
        return self._graph.number_of_nodes()